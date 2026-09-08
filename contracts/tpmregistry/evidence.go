package tpmregistry

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
	"github.com/cryptoecc/WorldLand/rlp"
	gotpm "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/credactivation"
)

const EvidenceVersion = 1

var (
	ekCertificateOID = asn1.ObjectIdentifier{2, 23, 133, 8, 1}
	nullifierDomain  = crypto.Keccak256Hash([]byte("WorldLand TPM nullifier v1"))
)

// Evidence is the canonical, non-interactive portion of an enrollment proof.
// Validator-specific activation and certification transcripts are deliberately
// excluded because they are created only after beginRegistration.
type Evidence struct {
	Version               uint32
	EKCertificateDER      []byte
	EKIntermediatesDER    [][]byte
	EKPublicArea          []byte
	AttestationPublicKey  []byte
	AttestationPublicArea []byte
	WorkPublicKey         []byte
	VRFPublicKey          []byte
	Profile               []byte
}

// Policy defines the certificate and TPM profile accepted by one validator epoch.
type Policy struct {
	CertificateProfile      string
	Version                 uint32
	RootCertificates        []*x509.Certificate
	RequireEKCertificateOID bool
	MaxEvidenceBytes        uint64
	AllowedProfileHashes    []common.Hash
	Clock                   func() time.Time
}

// ValidatedEvidence contains values derived only after all static checks pass.
type ValidatedEvidence struct {
	EvidenceHash    common.Hash
	EKName          []byte // canonical profile Name, not claimant-supplied TPM bytes
	AttestationName []byte
	DeviceNullifier common.Hash
	DID             common.Hash
	WorkKeyHash     common.Hash
	VRFKeyHash      common.Hash
	ProfileHash     common.Hash
}

// CanonicalBytes uses RLP with a versioned fixed-field structure. Changing the
// field order or meaning requires a new EvidenceVersion.
func (e *Evidence) CanonicalBytes() ([]byte, error) {
	if e == nil {
		return nil, errors.New("tpmregistry: nil evidence")
	}
	return rlp.EncodeToBytes(e)
}

func (e *Evidence) Hash() (common.Hash, error) {
	encoded, err := e.CanonicalBytes()
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(encoded), nil
}

func DecodeEvidence(encoded []byte) (*Evidence, error) {
	var evidence Evidence
	if len(encoded) == 0 {
		return nil, errors.New("tpmregistry: empty enrollment evidence")
	}
	if err := rlp.DecodeBytes(encoded, &evidence); err != nil {
		return nil, err
	}
	if evidence.Version != EvidenceVersion {
		return nil, fmt.Errorf("tpmregistry: unsupported evidence version %d", evidence.Version)
	}
	return &evidence, nil
}

// Digest commits to all validation inputs that governance assigns to an epoch.
func (p *Policy) Digest() (common.Hash, error) {
	if err := p.validateCertificatePolicy(); err != nil {
		return common.Hash{}, err
	}
	if p == nil || len(p.RootCertificates) == 0 {
		return common.Hash{}, errors.New("tpmregistry: policy has no EK roots")
	}
	rootHashes := make([]common.Hash, len(p.RootCertificates))
	for i, certificate := range p.RootCertificates {
		if certificate == nil {
			return common.Hash{}, errors.New("tpmregistry: nil EK root")
		}
		rootHashes[i] = crypto.Keccak256Hash(certificate.Raw)
	}
	sort.Slice(rootHashes, func(i, j int) bool { return bytes.Compare(rootHashes[i][:], rootHashes[j][:]) < 0 })
	profiles := append([]common.Hash(nil), p.AllowedProfileHashes...)
	sort.Slice(profiles, func(i, j int) bool { return bytes.Compare(profiles[i][:], profiles[j][:]) < 0 })
	encoded, err := rlp.EncodeToBytes(struct {
		EnrollmentRules         common.Hash
		Version                 uint32
		RootHashes              []common.Hash
		RequireEKCertificateOID bool
		MaxEvidenceBytes        uint64
		AllowedProfileHashes    []common.Hash
	}{enrollmentRulesDigest, p.Version, rootHashes, p.RequireEKCertificateOID, p.MaxEvidenceBytes, profiles})
	if err != nil {
		return common.Hash{}, err
	}
	if p.CertificateProfile == CertificateProfileGCPCAS {
		return crypto.Keccak256Hash([]byte("WorldLand certificate profile gcp-cas-v1\x00"), encoded), nil
	}
	return crypto.Keccak256Hash(encoded), nil
}

// DeviceNullifier implements H(chain context || canonical EK Name). Callers must
// obtain ekName from CanonicalEKName, not trust a claimant-supplied TPM Name.
func DeviceNullifier(chainID *big.Int, registry common.Address, ekName []byte) common.Hash {
	chainWord := make([]byte, 32)
	chainID.FillBytes(chainWord)
	return crypto.Keccak256Hash(nullifierDomain[:], chainWord, registry[:], ekName)
}

// ValidateEvidence validates the manufacturer identity and all static key bindings.
func (p *Policy) ValidateEvidence(chainID *big.Int, registry common.Address, evidence *Evidence) (*ValidatedEvidence, error) {
	if p == nil || evidence == nil {
		return nil, errors.New("tpmregistry: policy and evidence are required")
	}
	if err := p.validateCertificatePolicy(); err != nil {
		return nil, err
	}
	if evidence.Version != EvidenceVersion {
		return nil, fmt.Errorf("tpmregistry: unsupported evidence version %d", evidence.Version)
	}
	encoded, err := evidence.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	if p.MaxEvidenceBytes != 0 && uint64(len(encoded)) > p.MaxEvidenceBytes {
		return nil, fmt.Errorf("tpmregistry: evidence is %d bytes, limit %d", len(encoded), p.MaxEvidenceBytes)
	}
	certificate, err := x509.ParseCertificate(evidence.EKCertificateDER)
	if err != nil {
		return nil, fmt.Errorf("tpmregistry: parse EK certificate: %w", err)
	}
	roots := x509.NewCertPool()
	for _, root := range p.RootCertificates {
		roots.AddCert(root)
	}
	intermediates := x509.NewCertPool()
	for _, encodedIntermediate := range evidence.EKIntermediatesDER {
		certificate, err := x509.ParseCertificate(encodedIntermediate)
		if err != nil {
			return nil, fmt.Errorf("tpmregistry: parse EK intermediate: %w", err)
		}
		intermediates.AddCert(certificate)
	}
	currentTime := time.Now()
	if p.Clock != nil {
		currentTime = p.Clock()
	}
	if _, err := certificate.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: currentTime,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("tpmregistry: verify EK certificate: %w", err)
	}
	if p.RequireEKCertificateOID && !hasUnknownEKUsage(certificate) {
		return nil, errors.New("tpmregistry: EK certificate is missing tcg-kp-EKCertificate OID")
	}
	if p.CertificateProfile == CertificateProfileGCPCAS {
		if err := validateGCPEKCertificate(certificate); err != nil {
			return nil, err
		}
	}
	ekPublic, _, err := tpmwork.ParsePublicArea(evidence.EKPublicArea)
	if err != nil {
		return nil, fmt.Errorf("tpmregistry: parse EK public area: %w", err)
	}
	ekRSA, ok := ekPublic.(*rsa.PublicKey)
	certRSA, certOK := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || !certOK || ekRSA.E != certRSA.E || ekRSA.N.Cmp(certRSA.N) != 0 {
		return nil, errors.New("tpmregistry: EK certificate does not match RSA EK public area")
	}
	ekName, err := CanonicalEKName(evidence.EKPublicArea)
	if err != nil {
		return nil, err
	}
	attestationPublic, attestationName, err := tpmwork.ParsePublicArea(evidence.AttestationPublicArea)
	if err != nil {
		return nil, fmt.Errorf("tpmregistry: parse attestation public area: %w", err)
	}
	attestationRSA, ok := attestationPublic.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("tpmregistry: attestation key is not RSA")
	}
	derPublic, err := x509.ParsePKIXPublicKey(evidence.AttestationPublicKey)
	if err != nil {
		return nil, fmt.Errorf("tpmregistry: parse attestation public key: %w", err)
	}
	derRSA, ok := derPublic.(*rsa.PublicKey)
	if !ok || derRSA.E != attestationRSA.E || derRSA.N.Cmp(attestationRSA.N) != 0 {
		return nil, errors.New("tpmregistry: attestation public key does not match public area")
	}
	attestationRequired := uint32(tpmwork.ObjectFixedTPM | tpmwork.ObjectFixedParent | tpmwork.ObjectSensitiveDataOrigin | tpmwork.ObjectRestricted | tpmwork.ObjectSignEncrypt)
	if err := tpmwork.VerifyPublicAreaAttributes(evidence.AttestationPublicArea, attestationRequired, tpmwork.ObjectDecrypt); err != nil {
		return nil, fmt.Errorf("tpmregistry: invalid attestation-key attributes: %w", err)
	}
	if _, err := tpmwork.ParsePublicKey(evidence.WorkPublicKey); err != nil {
		return nil, err
	}
	vrfKeyHash, err := VRFKeyHash(evidence.VRFPublicKey)
	if err != nil {
		return nil, err
	}
	profileHash := crypto.Keccak256Hash(evidence.Profile)
	if len(p.AllowedProfileHashes) != 0 && !containsHash(p.AllowedProfileHashes, profileHash) {
		return nil, errors.New("tpmregistry: TPM profile is not allowed")
	}
	nullifier := DeviceNullifier(chainID, registry, ekName)
	return &ValidatedEvidence{
		EvidenceHash:    crypto.Keccak256Hash(encoded),
		EKName:          ekName,
		AttestationName: attestationName,
		DeviceNullifier: nullifier,
		DID:             DeriveDID(chainID, registry, nullifier),
		WorkKeyHash:     crypto.Keccak256Hash(evidence.WorkPublicKey),
		VRFKeyHash:      vrfKeyHash,
		ProfileHash:     profileHash,
	}, nil
}

// MakeCredential creates the two TPM2B payload contents sent to a claimant.
func MakeCredential(evidence *Evidence, secret []byte) (credentialBlob, encryptedSecret []byte, err error) {
	ekPublic, _, err := tpmwork.ParsePublicArea(evidence.EKPublicArea)
	if err != nil {
		return nil, nil, err
	}
	_, attestationName, err := tpmwork.ParsePublicArea(evidence.AttestationPublicArea)
	if err != nil {
		return nil, nil, err
	}
	if len(attestationName) != 34 || attestationName[0] != 0 || attestationName[1] != byte(gotpm.AlgSHA256) {
		return nil, nil, errors.New("tpmregistry: attestation Name is not SHA-256")
	}
	packedCredential, packedSecret, err := credactivation.Generate(
		&gotpm.HashValue{Alg: gotpm.AlgSHA256, Value: attestationName[2:]},
		ekPublic,
		16,
		secret,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("tpmregistry: make credential: %w", err)
	}
	credentialBlob, err = unwrapTPM2B(packedCredential)
	if err != nil {
		return nil, nil, err
	}
	encryptedSecret, err = unwrapTPM2B(packedSecret)
	if err != nil {
		return nil, nil, err
	}
	return credentialBlob, encryptedSecret, nil
}

func hasUnknownEKUsage(certificate *x509.Certificate) bool {
	for _, oid := range certificate.UnknownExtKeyUsage {
		if oid.Equal(ekCertificateOID) {
			return true
		}
	}
	return false
}

func containsHash(values []common.Hash, target common.Hash) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func unwrapTPM2B(encoded []byte) ([]byte, error) {
	if len(encoded) < 2 {
		return nil, errors.New("tpmregistry: short TPM2B value")
	}
	size := int(encoded[0])<<8 | int(encoded[1])
	if size != len(encoded)-2 {
		return nil, errors.New("tpmregistry: malformed TPM2B value")
	}
	return append([]byte(nil), encoded[2:]...), nil
}
