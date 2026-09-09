package tpmenroll

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	ethereum "github.com/cryptoecc/WorldLand"
	"github.com/cryptoecc/WorldLand/accounts/abi/bind"
	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
	"github.com/cryptoecc/WorldLand/ethclient"
)

type repeatedFlag []string

func (values *repeatedFlag) String() string { return strings.Join(*values, ",") }
func (values *repeatedFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type commandConfig struct {
	resume             bool
	action             string
	rpcURL             string
	registry           common.Address
	chainID            *big.Int
	controllerKey      string
	workKeyName        string
	attestationKeyName string
	createKeys         bool
	vrfPublicKeyFile   string
	profileFile        string
	intermediates      []string
	validators         []string
	ekHandle           uint64
	ekCertificateIndex uint64
	requestID          common.Hash
	identity           common.Hash
	waitActivation     bool
	timeout            time.Duration
}

type enrollmentBackend interface {
	bind.DeployBackend
	BlockNumber(context.Context) (uint64, error)
	HeaderByNumber(context.Context, *big.Int) (*types.Header, error)
	FilterLogs(context.Context, ethereum.FilterQuery) ([]types.Log, error)
}

type activationRegistry interface {
	ActivationBlock(context.Context, common.Hash) (*big.Int, error)
	Registration(context.Context, common.Hash) (tpmregistry.RegistrationState, error)
	Activate(*bind.TransactOpts, common.Hash) (*types.Transaction, error)
}

type producerEnrollmentRegistry interface {
	ProducerRequest(context.Context, common.Hash) (tpmregistry.ProducerRequestState, error)
	ProducerSlot(context.Context, common.Hash, uint64) (tpmregistry.ProducerSlotState, error)
	SubmitProducerResponse(*bind.TransactOpts, common.Hash, uint64, common.Hash, []byte) (*types.Transaction, error)
	FinalizeProducer(*bind.TransactOpts, common.Hash, tpmregistry.EnrollmentData) (*types.Transaction, error)
}

func Main() {
	var validators repeatedFlag
	var intermediates repeatedFlag
	action := flag.String("action", "register", "register, register-producer, activate, or cancel")
	rpcURL := flag.String("rpc", "http://127.0.0.1:8545", "WorldLand JSON-RPC URL")
	registryHex := flag.String("registry", "0x0000000000000000000000000000000000000801", "registry address")
	chainIDValue := flag.Int64("chain-id", 0, "chain ID")
	controllerKey := flag.String("controller-key", "", "controller secp256k1 private-key file")
	workKey := flag.String("work-key", "WorldLand-TPM-Work", "TPM work-key name (Linux: documented alias or persistent handle)")
	attestationKey := flag.String("attestation-key", "WorldLand-TPM-AIK", "TPM attestation-key name (Linux: documented alias or persistent handle)")
	createKeys := flag.Bool("create", false, "create missing TPM work and attestation keys")
	vrfPublicKey := flag.String("vrf-public-key", "", "33-byte compressed or 65-byte uncompressed controller secp256k1 public-key file")
	profile := flag.String("profile", "", "canonical TPM profile document")
	ekHandle := flag.Uint64("ek-handle", uint64(tpmwork.DefaultRSAEKHandle), "persistent RSA EK handle")
	ekCertificateIndex := flag.Uint64("ek-certificate-index", uint64(tpmwork.DefaultRSAEKCertificateIndex), "RSA EK certificate NV index")
	requestHex := flag.String("request-id", "", "request ID for cancel")
	identityHex := flag.String("identity", "", "TPM-bound consensus identity for activate")
	legacyDIDHex := flag.String("did", "", "deprecated alias for -identity")
	waitActivation := flag.Bool("wait-activation", false, "wait for activation block and send activate transaction")
	timeout := flag.Duration("timeout", 20*time.Minute, "whole operation timeout")
	flag.Var(&validators, "validator", "validator base URL (repeatable)")
	flag.Var(&intermediates, "ek-intermediate", "EK intermediate certificate PEM/DER (repeatable)")
	flag.Parse()

	if *chainIDValue <= 0 || *controllerKey == "" || !common.IsHexAddress(*registryHex) {
		flag.Usage()
		log.Fatal("chain-id, controller-key and a valid registry are required")
	}
	config := commandConfig{
		action: *action, rpcURL: *rpcURL, registry: common.HexToAddress(*registryHex),
		chainID: big.NewInt(*chainIDValue), controllerKey: *controllerKey,
		workKeyName: *workKey, attestationKeyName: *attestationKey, createKeys: *createKeys,
		vrfPublicKeyFile: *vrfPublicKey, profileFile: *profile,
		intermediates: intermediates, validators: validators,
		ekHandle: *ekHandle, ekCertificateIndex: *ekCertificateIndex,
		waitActivation: *waitActivation, timeout: *timeout,
	}
	if *requestHex != "" {
		config.requestID = common.HexToHash(*requestHex)
	}
	if *identityHex != "" && *legacyDIDHex != "" {
		log.Fatal("use only one of identity or the deprecated did flag")
	}
	if *identityHex != "" {
		config.identity = common.HexToHash(*identityHex)
	} else if *legacyDIDHex != "" {
		config.identity = common.HexToHash(*legacyDIDHex)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, config.timeout)
	defer cancel()
	if err := run(ctx, config); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, config commandConfig) error {
	backend, err := ethclient.DialContext(ctx, config.rpcURL)
	if err != nil {
		return err
	}
	defer backend.Close()
	return runWithClient(ctx, config, backend)
}

func runWithClient(ctx context.Context, config commandConfig, backend *ethclient.Client) error {
	controllerKey, err := readPrivateKey(config.controllerKey)
	if err != nil {
		return err
	}
	networkChainID, err := backend.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("tpmenroll: read RPC chain ID: %w", err)
	}
	if networkChainID.Cmp(config.chainID) != 0 {
		return fmt.Errorf("tpmenroll: configured chain ID %s does not match RPC chain ID %s", config.chainID, networkChainID)
	}
	registry, err := tpmregistry.NewRegistryClient(config.registry, backend)
	if err != nil {
		return err
	}
	auth, err := bind.NewKeyedTransactorWithChainID(controllerKey, config.chainID)
	if err != nil {
		return err
	}
	auth.Context = ctx

	switch config.action {
	case "activate":
		if config.identity == (common.Hash{}) {
			return errors.New("tpmenroll: identity is required for activate")
		}
		tx, err := registry.Activate(auth, config.identity)
		if err != nil {
			return err
		}
		return waitSuccessful(ctx, backend, "activate", tx)
	case "cancel":
		if config.requestID == (common.Hash{}) {
			return errors.New("tpmenroll: request-id is required for cancel")
		}
		tx, err := registry.CancelExpired(auth, config.requestID)
		if err != nil {
			return err
		}
		return waitSuccessful(ctx, backend, "cancel", tx)
	case "register":
		return register(ctx, config, backend, registry, auth, false)
	case "register-producer":
		return register(ctx, config, backend, registry, auth, true)
	default:
		return fmt.Errorf("tpmenroll: unknown action %q", config.action)
	}
}

func register(ctx context.Context, config commandConfig, backend *ethclient.Client, registry *tpmregistry.RegistryClient, auth *bind.TransactOpts, producerMode bool) error {
	if config.vrfPublicKeyFile == "" || config.profileFile == "" || (!producerMode && len(config.validators) == 0) {
		return errors.New("tpmenroll: vrf-public-key and profile are required; legacy registration also requires a validator")
	}
	if config.ekHandle > uint64(^uint32(0)) || config.ekCertificateIndex > uint64(^uint32(0)) {
		return errors.New("tpmenroll: EK handle and certificate index must fit uint32")
	}
	vrfPublicKey, err := readHexOrBinary(config.vrfPublicKeyFile)
	if err != nil {
		return err
	}
	vrfKeyHash, err := validateControllerVRFKey(vrfPublicKey, auth.From)
	if err != nil {
		return err
	}
	profile, err := os.ReadFile(config.profileFile)
	if err != nil {
		return err
	}
	intermediates, err := readCertificateDERs(config.intermediates)
	if err != nil {
		return err
	}
	workSigner, err := tpmwork.OpenPlatformSigner(config.workKeyName, config.createKeys)
	if err != nil {
		return err
	}
	defer workSigner.Close()
	activator, ok := interface{}(workSigner).(tpmwork.CredentialActivator)
	if !ok {
		return errors.New("tpmenroll: TPM backend does not support credential activation")
	}
	certifier, ok := interface{}(workSigner).(tpmwork.KeyCertifier)
	if !ok {
		return errors.New("tpmenroll: TPM backend does not support key certification")
	}
	identity, err := activator.EnrollmentIdentity(
		config.attestationKeyName, config.createKeys,
		uint32(config.ekHandle), uint32(config.ekCertificateIndex),
	)
	if err != nil {
		return err
	}
	evidence := tpmregistry.Evidence{
		Version:          tpmregistry.EvidenceVersion,
		EKCertificateDER: identity.EKCertificateDER, EKIntermediatesDER: intermediates,
		EKPublicArea:          identity.EKPublicArea,
		AttestationPublicKey:  identity.AttestationPublicKey,
		AttestationPublicArea: identity.AttestationPublicArea,
		WorkPublicKey:         workSigner.PublicKey(), VRFPublicKey: vrfPublicKey, Profile: profile,
	}
	evidenceHash, err := evidence.Hash()
	if err != nil {
		return err
	}
	ekName, err := tpmregistry.CanonicalEKName(identity.EKPublicArea)
	if err != nil {
		return fmt.Errorf("tpmenroll: canonical EK: %w", err)
	}
	nullifier := tpmregistry.DeviceNullifier(config.chainID, config.registry, ekName)
	identityHash := tpmregistry.DeriveConsensusIdentity(config.chainID, config.registry, nullifier)
	enrollment := tpmregistry.EnrollmentData{
		DID: identityHash, WorkKeyHash: crypto.Keccak256Hash(evidence.WorkPublicKey),
		VRFKeyHash:  vrfKeyHash,
		ProfileHash: crypto.Keccak256Hash(evidence.Profile), DeviceNullifier: nullifier,
		EvidenceHash: evidenceHash,
	}
	if config.identity != (common.Hash{}) && config.identity != identityHash {
		return errors.New("tpmenroll: configured mining identity differs from local TPM identity")
	}
	if config.resume && producerMode {
		done, err := resumeProducer(ctx, config, backend, registry, auth, activator, certifier, enrollment)
		if done || err != nil {
			return err
		}
	}

	nonce, err := registry.RequestNonce(ctx, auth.From)
	if err != nil {
		return err
	}
	collateral, err := registry.FixedCollateral(ctx)
	if err != nil {
		return err
	}
	auth.Value = collateral
	var beginTransaction *types.Transaction
	if producerMode {
		evidenceBundle, encodeErr := evidence.CanonicalBytes()
		if encodeErr != nil {
			return encodeErr
		}
		beginTransaction, err = registry.BeginProducer(auth, enrollment, evidenceBundle)
	} else {
		beginTransaction, err = registry.Begin(auth, enrollment)
	}
	if err != nil {
		return fmt.Errorf("tpmenroll: begin registration: %w", err)
	}
	if err := waitSuccessful(ctx, backend, "begin registration", beginTransaction); err != nil {
		return err
	}
	auth.Value = new(big.Int)
	requestID := tpmregistry.DeriveRequestID(config.registry, config.chainID, auth.From, nonce)
	if producerMode {
		producerRequest, requestErr := registry.ProducerRequest(ctx, requestID)
		if requestErr != nil {
			return requestErr
		}
		log.Printf(
			"producer request %s opened for consensus identity %s; slots %d-%d, threshold %d, response deadline %d",
			requestID, identityHash, producerRequest.FirstSlot, producerRequest.LastSlot,
			producerRequest.Threshold, producerRequest.ResponseDeadline,
		)
		if err := completeProducerRegistration(
			ctx, config, backend, registry, auth, activator, certifier,
			requestID, enrollment, producerRequest,
		); err != nil {
			return err
		}
		return finishActivation(ctx, config, backend, registry, auth, identityHash)
	}
	requestState, err := registry.Request(ctx, requestID)
	if err != nil {
		return err
	}
	policyDigest, err := registry.PolicyDigest(ctx, requestState.ValidatorEpoch)
	if err != nil {
		return err
	}
	statement := tpmregistry.EnrollmentStatement{
		RequestID: requestID, DID: enrollment.DID, Controller: auth.From,
		WorkKeyHash: enrollment.WorkKeyHash, VRFKeyHash: enrollment.VRFKeyHash,
		ProfileHash: enrollment.ProfileHash, DeviceNullifier: enrollment.DeviceNullifier,
		PolicyDigest: policyDigest, EvidenceHash: enrollment.EvidenceHash,
		ValidatorEpoch: requestState.ValidatorEpoch, Deadline: requestState.Deadline,
	}
	if statement.StructHash() != requestState.StatementHash {
		return errors.New("tpmenroll: locally reconstructed statement differs from contract")
	}
	threshold, err := registry.Threshold(ctx, requestState.ValidatorEpoch)
	if err != nil {
		return err
	}
	log.Printf("request %s opened for consensus identity %s; collecting %d approvals", requestID, identityHash, threshold)
	approvals := make([][]byte, 0, threshold)
	approvedBy := make(map[common.Address]struct{}, threshold)
	for _, endpoint := range config.validators {
		approval, signer, err := requestApproval(ctx, endpoint, statement, evidence, activator, certifier, config)
		if err != nil {
			log.Printf("validator %s rejected or failed: %v", endpoint, err)
			continue
		}
		member, err := registry.IsValidator(ctx, requestState.ValidatorEpoch, signer)
		if err != nil {
			return fmt.Errorf("tpmenroll: check validator %s membership: %w", signer, err)
		}
		if !member {
			log.Printf("validator %s returned signer %s outside epoch %d", endpoint, signer, requestState.ValidatorEpoch)
			continue
		}
		if _, duplicate := approvedBy[signer]; duplicate {
			log.Printf("validator %s returned duplicate signer %s", endpoint, signer)
			continue
		}
		approvedBy[signer] = struct{}{}
		approvals = append(approvals, approval)
		if len(approvals) >= int(threshold) {
			break
		}
	}
	if len(approvals) < int(threshold) {
		return fmt.Errorf("tpmenroll: collected %d of %d approvals; request %s may be cancelled after block %d", len(approvals), threshold, requestID, requestState.Deadline)
	}
	finalizeTransaction, err := registry.Finalize(auth, requestID, enrollment, approvals)
	if err != nil {
		return fmt.Errorf("tpmenroll: finalize registration: %w", err)
	}
	if err := waitSuccessful(ctx, backend, "finalize registration", finalizeTransaction); err != nil {
		return err
	}
	return finishActivation(ctx, config, backend, registry, auth, identityHash)
}

func validateControllerVRFKey(encoded []byte, controller common.Address) (common.Hash, error) {
	canonical, err := tpmregistry.CanonicalVRFPublicKey(encoded)
	if err != nil {
		return common.Hash{}, fmt.Errorf("tpmenroll: VRF public key: %w", err)
	}
	publicKey, err := crypto.DecompressPubkey(canonical)
	if err != nil {
		return common.Hash{}, err
	}
	if crypto.PubkeyToAddress(*publicKey) != controller {
		return common.Hash{}, errors.New("tpmenroll: VRF public key must belong to the registration controller and mining coinbase")
	}
	return tpmregistry.VRFKeyHash(canonical)
}

func finishActivation(ctx context.Context, config commandConfig, backend enrollmentBackend, registry activationRegistry, auth *bind.TransactOpts, identityHash common.Hash) error {
	activationBlock, err := registry.ActivationBlock(ctx, identityHash)
	if err != nil {
		return err
	}
	log.Printf("consensus identity %s finalized; activation block %s", identityHash, activationBlock)
	if !config.waitActivation {
		return nil
	}
	for {
		registration, err := registry.Registration(ctx, identityHash)
		if err != nil {
			return err
		}
		if registration.Active {
			return nil
		}
		blockNumber, err := backend.BlockNumber(ctx)
		if err != nil {
			return err
		}
		if new(big.Int).SetUint64(blockNumber).Cmp(activationBlock) >= 0 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	activateTransaction, err := registry.Activate(auth, identityHash)
	if err != nil {
		if registration, readErr := registry.Registration(ctx, identityHash); readErr == nil && registration.Active {
			return nil
		}
		return err
	}
	if err := waitSuccessful(ctx, backend, "activate", activateTransaction); err != nil {
		if registration, readErr := registry.Registration(ctx, identityHash); readErr == nil && registration.Active {
			return nil
		}
		return err
	}
	return nil
}

func completeProducerRegistration(
	ctx context.Context,
	config commandConfig,
	backend enrollmentBackend,
	registry producerEnrollmentRegistry,
	auth *bind.TransactOpts,
	activator tpmwork.CredentialActivator,
	certifier tpmwork.KeyCertifier,
	requestID common.Hash,
	enrollment tpmregistry.EnrollmentData,
	producerRequest tpmregistry.ProducerRequestState,
) error {
	for {
		current, err := backend.BlockNumber(ctx)
		if err != nil {
			return err
		}
		producerRequest, err = registry.ProducerRequest(ctx, requestID)
		if err != nil {
			return err
		}
		if producerRequest.Threshold == 0 {
			// A reorg can temporarily remove the begin transaction. A missing
			// request is not a zero-of-zero approval quorum.
			if err := waitEnrollmentPoll(ctx); err != nil {
				return err
			}
			continue
		}
		if producerRequest.Approvals >= producerRequest.Threshold {
			tx, err := registry.FinalizeProducer(auth, requestID, enrollment)
			if err != nil {
				return fmt.Errorf("tpmenroll: finalize producer registration: %w", err)
			}
			return waitSuccessful(ctx, backend, "finalize producer registration", tx)
		}
		if current > producerRequest.ResponseDeadline {
			return fmt.Errorf(
				"tpmenroll: producer request expired with %d of %d approvals",
				producerRequest.Approvals, producerRequest.Threshold,
			)
		}
		if current >= producerRequest.FirstSlot {
			toBlock := current
			if toBlock > producerRequest.LastSlot {
				toBlock = producerRequest.LastSlot
			}
			logs, err := backend.FilterLogs(ctx, ethereum.FilterQuery{
				FromBlock: new(big.Int).SetUint64(producerRequest.FirstSlot),
				ToBlock:   new(big.Int).SetUint64(toBlock),
				Addresses: []common.Address{config.registry},
				Topics: [][]common.Hash{
					{tpmregistry.ProducerEventTopic("ProducerChallengePublished")}, {requestID},
				},
			})
			if err != nil {
				return fmt.Errorf("tpmenroll: filter producer challenges: %w", err)
			}
			for _, entry := range logs {
				challenge, err := tpmregistry.ParseProducerChallengeEvent(entry)
				if err != nil || challenge.Removed {
					continue
				}
				slotState, currentChallenge, err := readCurrentChallenge(ctx, backend, registry, entry, challenge)
				if err != nil {
					return err
				}
				if !currentChallenge || slotState.Responded {
					continue
				}
				activated, err := activator.ActivateCredential(
					config.attestationKeyName, uint32(config.ekHandle),
					challenge.CredentialBlob, challenge.EncryptedSecret,
				)
				if err != nil {
					return fmt.Errorf("tpmenroll: activate slot %d: %w", challenge.Slot, err)
				}
				if len(activated) != common.HashLength {
					return fmt.Errorf("tpmenroll: slot %d secret is %d bytes", challenge.Slot, len(activated))
				}
				certifyChallenge := tpmregistry.ProducerCertifyChallenge(
					config.chainID, config.registry, requestID, challenge.Slot, challenge.Commitment,
				)
				certifyChallenge = researchResponseChallenge(config.chainID, config.registry, requestID, challenge.Slot, producerRequest.FirstSlot, challenge.Commitment, certifyChallenge)
				certification, err := certifier.CertifyWorkKey(
					config.attestationKeyName, false, certifyChallenge[:],
				)
				if err != nil {
					return fmt.Errorf("tpmenroll: certify slot %d: %w", challenge.Slot, err)
				}
				evidence := tpmregistry.ProducerResponseEvidence{
					Version: tpmregistry.ProducerEvidenceVersion, WorkCertification: *certification,
				}
				researchMutateResponse(config.chainID, challenge.Slot, producerRequest.FirstSlot, &evidence.WorkCertification)
				evidenceBundle, err := evidence.CanonicalBytes()
				if err != nil {
					return err
				}
				// TPM operations can take longer than a block. Recheck the exact
				// canonical challenge before publishing its response.
				latestSlot, currentChallenge, err := readCurrentChallenge(ctx, backend, registry, entry, challenge)
				if err != nil {
					return err
				}
				if !currentChallenge || latestSlot.Responded {
					continue
				}
				tx, err := registry.SubmitProducerResponse(
					auth, requestID, challenge.Slot, common.BytesToHash(activated), evidenceBundle,
				)
				if err != nil {
					if slot, same, readErr := readCurrentChallenge(ctx, backend, registry, entry, challenge); readErr == nil && (!same || slot.Responded) {
						continue
					}
					return fmt.Errorf("tpmenroll: submit slot %d response: %w", challenge.Slot, err)
				}
				if err := waitSuccessful(ctx, backend, fmt.Sprintf("producer response slot %d", challenge.Slot), tx); err != nil {
					if slot, same, readErr := readCurrentChallenge(ctx, backend, registry, entry, challenge); readErr == nil && (!same || slot.Responded) {
						continue
					}
					return err
				}
			}
		}
		if err := waitEnrollmentPoll(ctx); err != nil {
			return err
		}
	}
}

func waitEnrollmentPoll(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(2 * time.Second):
		return nil
	}
}

// readCurrentChallenge deliberately has no responded-by-height cache: a reorg
// may replace a challenge at the same slot or remove its previously mined reply.
func readCurrentChallenge(ctx context.Context, backend enrollmentBackend, registry producerEnrollmentRegistry, entry types.Log, challenge tpmregistry.ProducerChallengeEvent) (tpmregistry.ProducerSlotState, bool, error) {
	header, err := backend.HeaderByNumber(ctx, new(big.Int).SetUint64(entry.BlockNumber))
	if err != nil {
		if errors.Is(err, ethereum.NotFound) {
			return tpmregistry.ProducerSlotState{}, false, nil
		}
		return tpmregistry.ProducerSlotState{}, false, err
	}
	if header == nil || header.Hash() != entry.BlockHash || challenge.Removed || entry.Removed || entry.BlockNumber != challenge.Slot {
		return tpmregistry.ProducerSlotState{}, false, nil
	}
	slot, err := registry.ProducerSlot(ctx, challenge.RequestID, challenge.Slot)
	if err != nil {
		return slot, false, err
	}
	credentialHash, err := tpmregistry.CredentialHash(challenge.CredentialBlob, challenge.EncryptedSecret)
	if err != nil {
		return slot, false, err
	}
	return slot, slot.Producer == challenge.Producer && slot.Commitment == challenge.Commitment && slot.CredentialHash == credentialHash, nil
}

func requestApproval(ctx context.Context, endpoint string, statement tpmregistry.EnrollmentStatement, evidence tpmregistry.Evidence, activator tpmwork.CredentialActivator, certifier tpmwork.KeyCertifier, config commandConfig) ([]byte, common.Address, error) {
	httpClient := &http.Client{Timeout: 2 * time.Minute}
	var challenge tpmregistry.ChallengeResponse
	if err := postJSON(ctx, httpClient, strings.TrimRight(endpoint, "/")+"/v1/challenge", tpmregistry.ChallengeRequest{Statement: statement, Evidence: evidence}, &challenge); err != nil {
		return nil, common.Address{}, err
	}
	activated, err := activator.ActivateCredential(config.attestationKeyName, uint32(config.ekHandle), challenge.CredentialBlob, challenge.EncryptedSecret)
	if err != nil {
		return nil, common.Address{}, err
	}
	certification, err := certifier.CertifyWorkKey(config.attestationKeyName, false, challenge.CertifyChallenge)
	if err != nil {
		return nil, common.Address{}, err
	}
	var approval tpmregistry.ApprovalResponse
	if err := postJSON(ctx, httpClient, strings.TrimRight(endpoint, "/")+"/v1/approve", tpmregistry.ApprovalRequest{
		SessionID: challenge.SessionID, ActivatedSecret: activated, WorkCertification: *certification,
	}, &approval); err != nil {
		return nil, common.Address{}, err
	}
	digest := tpmregistry.ApprovalDigest(config.chainID, config.registry, statement)
	signer, err := tpmregistry.RecoverApprovalSigner(digest, approval.Signature)
	if err != nil {
		return nil, common.Address{}, err
	}
	if signer != approval.Validator {
		return nil, common.Address{}, errors.New("tpmenroll: validator response address does not match signature")
	}
	return approval.Signature, signer, nil
}

func postJSON(ctx context.Context, client *http.Client, url string, input, output interface{}) error {
	encoded, err := json.Marshal(input)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("validator returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, output); err != nil {
		return err
	}
	return nil
}

func waitSuccessful(ctx context.Context, backend bind.DeployBackend, operation string, transaction *types.Transaction) error {
	log.Printf("%s transaction: %s", operation, transaction.Hash())
	receipt, err := bind.WaitMined(ctx, backend, transaction)
	if err != nil {
		return err
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return fmt.Errorf("tpmenroll: %s reverted in transaction %s", operation, transaction.Hash())
	}
	return nil
}

func readPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return crypto.HexToECDSA(strings.TrimPrefix(strings.TrimSpace(string(encoded)), "0x"))
}

func readHexOrBinary(path string) ([]byte, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(encoded))
	hexValue := strings.TrimPrefix(trimmed, "0x")
	if decoded, err := hex.DecodeString(hexValue); err == nil && len(decoded) != 0 {
		return decoded, nil
	}
	return encoded, nil
}

func readCertificateDERs(paths []string) ([][]byte, error) {
	result := make([][]byte, 0, len(paths))
	for _, path := range paths {
		encoded, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if block, _ := pem.Decode(encoded); block != nil {
			encoded = block.Bytes
		}
		certificate, err := x509.ParseCertificate(encoded)
		if err != nil {
			return nil, fmt.Errorf("tpmenroll: parse intermediate %s: %w", path, err)
		}
		result = append(result, certificate.Raw)
	}
	return result, nil
}
