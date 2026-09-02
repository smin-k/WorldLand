package tpmregistry

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
)

const (
	defaultValidatorSessionTTL  = 5 * time.Minute
	defaultValidatorBodyLimit   = 2 << 20
	defaultValidatorMaxSessions = 4096
)

// RequestVerifier prevents validators from signing statements that do not
// correspond to a live beginRegistration request in canonical chain state.
type RequestVerifier interface {
	VerifyRegistrationRequest(context.Context, EnrollmentStatement) error
}

type ValidatorConfig struct {
	ChainID                *big.Int
	Registry               common.Address
	Policy                 *Policy
	SigningKey             *ecdsa.PrivateKey
	RequestVerifier        RequestVerifier
	AllowUnverifiedRequest bool
	SessionTTL             time.Duration
	MaxRequestBytes        int64
	MaxSessions            int
}

type ChallengeRequest struct {
	Statement EnrollmentStatement `json:"statement"`
	Evidence  Evidence            `json:"evidence"`
}

type ChallengeResponse struct {
	SessionID        common.Hash `json:"sessionId"`
	CredentialBlob   []byte      `json:"credentialBlob"`
	EncryptedSecret  []byte      `json:"encryptedSecret"`
	CertifyChallenge []byte      `json:"certifyChallenge"`
	ExpiresAt        time.Time   `json:"expiresAt"`
}

type ApprovalRequest struct {
	SessionID         common.Hash              `json:"sessionId"`
	ActivatedSecret   []byte                   `json:"activatedSecret"`
	WorkCertification tpmwork.KeyCertification `json:"workCertification"`
}

type ApprovalResponse struct {
	Validator common.Address `json:"validator"`
	Signature []byte         `json:"signature"`
}

type validatorSession struct {
	statement        EnrollmentStatement
	evidence         Evidence
	secret           []byte
	certifyChallenge []byte
	expiresAt        time.Time
}

// ValidatorService performs one fresh credential activation and work-key
// certification before issuing an attributable EIP-712 approval.
type ValidatorService struct {
	config       ValidatorConfig
	policyDigest common.Hash
	address      common.Address
	mu           sync.Mutex
	sessions     map[common.Hash]validatorSession
}

func NewValidatorService(config ValidatorConfig) (*ValidatorService, error) {
	if config.ChainID == nil || config.ChainID.Sign() <= 0 {
		return nil, errors.New("tpmregistry: validator chain ID is required")
	}
	if config.Registry == (common.Address{}) || config.SigningKey == nil || config.Policy == nil {
		return nil, errors.New("tpmregistry: validator registry, policy and signing key are required")
	}
	if config.RequestVerifier == nil && !config.AllowUnverifiedRequest {
		return nil, errors.New("tpmregistry: on-chain request verifier is required")
	}
	if config.SessionTTL == 0 {
		config.SessionTTL = defaultValidatorSessionTTL
	}
	if config.SessionTTL < 0 {
		return nil, errors.New("tpmregistry: invalid validator session TTL")
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = defaultValidatorBodyLimit
	}
	if config.MaxSessions == 0 {
		config.MaxSessions = defaultValidatorMaxSessions
	}
	if config.MaxSessions < 0 {
		return nil, errors.New("tpmregistry: invalid validator session limit")
	}
	digest, err := config.Policy.Digest()
	if err != nil {
		return nil, err
	}
	return &ValidatorService{
		config:       config,
		policyDigest: digest,
		address:      crypto.PubkeyToAddress(config.SigningKey.PublicKey),
		sessions:     make(map[common.Hash]validatorSession),
	}, nil
}

func (service *ValidatorService) Address() common.Address   { return service.address }
func (service *ValidatorService) PolicyDigest() common.Hash { return service.policyDigest }

func (service *ValidatorService) Challenge(ctx context.Context, request ChallengeRequest) (*ChallengeResponse, error) {
	validated, err := service.config.Policy.ValidateEvidence(service.config.ChainID, service.config.Registry, &request.Evidence)
	if err != nil {
		return nil, err
	}
	if err := matchStatement(request.Statement, validated, service.policyDigest); err != nil {
		return nil, err
	}
	if service.config.RequestVerifier != nil {
		if err := service.config.RequestVerifier.VerifyRegistrationRequest(ctx, request.Statement); err != nil {
			return nil, fmt.Errorf("tpmregistry: verify on-chain request: %w", err)
		}
	}
	secret := make([]byte, 32)
	certifyChallenge := make([]byte, 32)
	sessionBytes := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if _, err := rand.Read(certifyChallenge); err != nil {
		return nil, err
	}
	if _, err := rand.Read(sessionBytes); err != nil {
		return nil, err
	}
	credentialBlob, encryptedSecret, err := MakeCredential(&request.Evidence, secret)
	if err != nil {
		return nil, err
	}
	sessionID := common.BytesToHash(sessionBytes)
	expiresAt := time.Now().Add(service.config.SessionTTL)
	service.mu.Lock()
	service.pruneExpiredLocked(time.Now())
	if len(service.sessions) >= service.config.MaxSessions {
		service.mu.Unlock()
		return nil, errors.New("tpmregistry: validator session capacity reached")
	}
	service.sessions[sessionID] = validatorSession{
		statement: request.Statement, evidence: request.Evidence,
		secret: secret, certifyChallenge: certifyChallenge, expiresAt: expiresAt,
	}
	service.mu.Unlock()
	return &ChallengeResponse{
		SessionID: sessionID, CredentialBlob: credentialBlob,
		EncryptedSecret: encryptedSecret, CertifyChallenge: certifyChallenge,
		ExpiresAt: expiresAt,
	}, nil
}

func (service *ValidatorService) Approve(_ context.Context, request ApprovalRequest) (*ApprovalResponse, error) {
	service.mu.Lock()
	session, ok := service.sessions[request.SessionID]
	delete(service.sessions, request.SessionID) // every activation challenge is one-shot
	service.mu.Unlock()
	if !ok {
		return nil, errors.New("tpmregistry: validator session not found")
	}
	if time.Now().After(session.expiresAt) {
		return nil, errors.New("tpmregistry: validator session expired")
	}
	if len(request.ActivatedSecret) != len(session.secret) || subtle.ConstantTimeCompare(request.ActivatedSecret, session.secret) != 1 {
		return nil, errors.New("tpmregistry: activated credential mismatch")
	}
	certification := &request.WorkCertification
	if subtle.ConstantTimeCompare(certification.Challenge, session.certifyChallenge) != 1 {
		return nil, errors.New("tpmregistry: work certification challenge mismatch")
	}
	if err := tpmwork.VerifyKeyCertification(certification); err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(certification.WorkPublicKey, session.evidence.WorkPublicKey) != 1 ||
		subtle.ConstantTimeCompare(certification.AttestationPublicKey, session.evidence.AttestationPublicKey) != 1 ||
		subtle.ConstantTimeCompare(certification.AttestationPublicArea, session.evidence.AttestationPublicArea) != 1 {
		return nil, errors.New("tpmregistry: certified keys differ from committed evidence")
	}
	digest := ApprovalDigest(service.config.ChainID, service.config.Registry, session.statement)
	signature, err := crypto.Sign(digest[:], service.config.SigningKey)
	if err != nil {
		return nil, err
	}
	return &ApprovalResponse{Validator: service.address, Signature: signature}, nil
}

func (service *ValidatorService) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/challenge", service.serveChallenge)
	mux.HandleFunc("/v1/approve", service.serveApprove)
	mux.HandleFunc("/healthz", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, map[string]interface{}{
			"validator": service.address, "policyDigest": service.policyDigest,
		})
	})
	return mux
}

func (service *ValidatorService) serveChallenge(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input ChallengeRequest
	if err := decodeLimitedJSON(response, request, service.config.MaxRequestBytes, &input); err != nil {
		return
	}
	result, err := service.Challenge(request.Context(), input)
	if err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (service *ValidatorService) serveApprove(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input ApprovalRequest
	if err := decodeLimitedJSON(response, request, service.config.MaxRequestBytes, &input); err != nil {
		return
	}
	result, err := service.Approve(request.Context(), input)
	if err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func matchStatement(statement EnrollmentStatement, evidence *ValidatedEvidence, policyDigest common.Hash) error {
	if statement.RequestID == (common.Hash{}) || statement.Controller == (common.Address{}) {
		return errors.New("tpmregistry: incomplete enrollment statement")
	}
	checks := []struct {
		name string
		got  common.Hash
		want common.Hash
	}{
		{"DID", statement.DID, evidence.DID},
		{"work key", statement.WorkKeyHash, evidence.WorkKeyHash},
		{"VRF key", statement.VRFKeyHash, evidence.VRFKeyHash},
		{"profile", statement.ProfileHash, evidence.ProfileHash},
		{"device nullifier", statement.DeviceNullifier, evidence.DeviceNullifier},
		{"policy", statement.PolicyDigest, policyDigest},
		{"evidence", statement.EvidenceHash, evidence.EvidenceHash},
	}
	for _, check := range checks {
		if check.got != check.want {
			return fmt.Errorf("tpmregistry: enrollment %s hash mismatch", check.name)
		}
	}
	if statement.ValidatorEpoch == 0 || statement.Deadline == 0 {
		return errors.New("tpmregistry: invalid enrollment epoch or deadline")
	}
	return nil
}

func (service *ValidatorService) pruneExpiredLocked(now time.Time) {
	for id, session := range service.sessions {
		if now.After(session.expiresAt) {
			delete(service.sessions, id)
		}
	}
}

func decodeLimitedJSON(response http.ResponseWriter, request *http.Request, limit int64, target interface{}) error {
	request.Body = http.MaxBytesReader(response, request.Body, limit)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			err = errors.New("multiple JSON values are not allowed")
		}
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return err
	}
	return nil
}

func writeJSON(response http.ResponseWriter, status int, value interface{}) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
