package tpmregistry_test

import (
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/cryptoecc/WorldLand/accounts/abi/bind"
	"github.com/cryptoecc/WorldLand/accounts/abi/bind/backends"
	"github.com/cryptoecc/WorldLand/common"
	. "github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/core"
	"github.com/cryptoecc/WorldLand/crypto"
)

func TestThresholdRegistryContractLifecycle(t *testing.T) {
	ctx := context.Background()
	chainID := big.NewInt(1337)
	controllerKey, _ := crypto.GenerateKey()
	validatorOne, _ := crypto.GenerateKey()
	validatorTwo, _ := crypto.GenerateKey()
	controller := crypto.PubkeyToAddress(controllerKey.PublicKey)
	validators := []common.Address{
		crypto.PubkeyToAddress(validatorOne.PublicKey), crypto.PubkeyToAddress(validatorTwo.PublicKey),
	}
	policyDigest := crypto.Keccak256Hash([]byte("integration policy"))
	config := PredeployConfig{
		Address: DefaultRegistryAddress, FixedCollateral: new(big.Int), Governor: controller,
		RegistrationTTL: 90, Validators: validators, Threshold: 2, PolicyDigest: policyDigest,
		ProducerSlotCount: 6, ProducerThreshold: 4, ProducerSlotDelay: 2,
		ProducerResponseWindow: 12, ProducerPolicyDigest: crypto.Keccak256Hash([]byte("producer policy")),
	}
	code, err := RegistryRuntimeCode()
	if err != nil {
		t.Fatal(err)
	}
	storage, err := PredeployStorage(config)
	if err != nil {
		t.Fatal(err)
	}
	backend := backends.NewSimulatedBackend(core.GenesisAlloc{
		controller:     {Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)},
		config.Address: {Code: code, Storage: storage, Balance: new(big.Int)},
	}, 15_000_000)
	defer backend.Close()
	client, err := NewRegistryClient(config.Address, backend)
	if err != nil {
		t.Fatal(err)
	}
	for _, validator := range validators {
		member, err := client.IsValidator(ctx, 1, validator)
		if err != nil || !member {
			t.Fatalf("validator %s membership = %v, error %v", validator, member, err)
		}
	}
	nonMember, err := client.IsValidator(ctx, 1, controller)
	if err != nil || nonMember {
		t.Fatalf("controller validator membership = %v, error %v", nonMember, err)
	}
	auth, err := bind.NewKeyedTransactorWithChainID(controllerKey, chainID)
	if err != nil {
		t.Fatal(err)
	}
	auth.Context = ctx
	nullifier := crypto.Keccak256Hash([]byte("integration nullifier"))
	enrollment := EnrollmentData{
		DID:         DeriveDID(chainID, config.Address, nullifier),
		WorkKeyHash: crypto.Keccak256Hash([]byte("work")), VRFKeyHash: crypto.Keccak256Hash([]byte("vrf")),
		ProfileHash: crypto.Keccak256Hash([]byte("profile")), DeviceNullifier: nullifier,
		EvidenceHash: crypto.Keccak256Hash([]byte("evidence")),
	}
	nonce, err := client.RequestNonce(ctx, controller)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := client.Begin(auth, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	backend.Commit()
	receipt, err := backend.TransactionReceipt(ctx, transaction.Hash())
	if err != nil || receipt.Status == 0 {
		t.Fatalf("begin receipt status %v, error %v", receipt, err)
	}
	requestID := DeriveRequestID(config.Address, chainID, controller, nonce)
	request, err := client.Request(ctx, requestID)
	if err != nil {
		t.Fatal(err)
	}
	statement := EnrollmentStatement{
		RequestID: requestID, DID: enrollment.DID, Controller: controller,
		WorkKeyHash: enrollment.WorkKeyHash, VRFKeyHash: enrollment.VRFKeyHash,
		ProfileHash: enrollment.ProfileHash, DeviceNullifier: enrollment.DeviceNullifier,
		PolicyDigest: policyDigest, EvidenceHash: enrollment.EvidenceHash,
		ValidatorEpoch: request.ValidatorEpoch, Deadline: request.Deadline,
	}
	if statement.StructHash() != request.StatementHash {
		t.Fatal("Go statement hash differs from Solidity request")
	}
	digest := ApprovalDigest(chainID, config.Address, statement)
	approvalOne, _ := crypto.Sign(digest[:], validatorOne)
	approvalTwo, _ := crypto.Sign(digest[:], validatorTwo)
	if _, err := client.Finalize(auth, requestID, enrollment, [][]byte{approvalOne}); err == nil {
		t.Fatal("registration with fewer than threshold approvals was accepted")
	}
	if _, err := client.Finalize(auth, requestID, enrollment, [][]byte{approvalOne, approvalOne}); err == nil {
		t.Fatal("registration with duplicate validator approvals was accepted")
	}
	transaction, err = client.Finalize(auth, requestID, enrollment, [][]byte{approvalOne, approvalTwo})
	if err != nil {
		t.Fatal(err)
	}
	backend.Commit()
	receipt, err = backend.TransactionReceipt(ctx, transaction.Hash())
	if err != nil || receipt.Status == 0 {
		t.Fatalf("finalize receipt status %v, error %v", receipt, err)
	}
	registration, err := client.Registration(ctx, enrollment.DID)
	if err != nil {
		t.Fatal(err)
	}
	if !registration.Active || registration.Controller != controller || registration.WorkKeyHash != enrollment.WorkKeyHash {
		t.Fatalf("unexpected registration: %+v", registration)
	}
	if _, err := client.Begin(auth, enrollment); err == nil {
		t.Fatal("duplicate DID/nullifier registration was accepted")
	}
	transaction, err = client.Revoke(auth, enrollment.DID)
	if err != nil {
		t.Fatal(err)
	}
	backend.Commit()
	receipt, err = backend.TransactionReceipt(ctx, transaction.Hash())
	if err != nil || receipt.Status == 0 {
		t.Fatalf("revoke receipt status %v, error %v", receipt, err)
	}
	if _, err := client.Begin(auth, enrollment); err == nil {
		t.Fatal("revocation made a consumed DID/nullifier reusable")
	}

	// Two requests for one physical-device nullifier may be pending at once,
	// but finalization must be atomic: after either request consumes the
	// nullifier, the other request cannot create a second identity/key binding.
	raceNullifier := crypto.Keccak256Hash([]byte("concurrent physical TPM"))
	raceOne := EnrollmentData{
		DID:         DeriveDID(chainID, config.Address, raceNullifier),
		WorkKeyHash: crypto.Keccak256Hash([]byte("race work one")), VRFKeyHash: crypto.Keccak256Hash([]byte("race vrf one")),
		ProfileHash: crypto.Keccak256Hash([]byte("race profile")), DeviceNullifier: raceNullifier,
		EvidenceHash: crypto.Keccak256Hash([]byte("race evidence one")),
	}
	raceTwo := raceOne
	raceTwo.WorkKeyHash = crypto.Keccak256Hash([]byte("race work two"))
	raceTwo.VRFKeyHash = crypto.Keccak256Hash([]byte("race vrf two"))
	raceTwo.EvidenceHash = crypto.Keccak256Hash([]byte("race evidence two"))
	beginAndApprove := func(candidate EnrollmentData) (common.Hash, [][]byte) {
		t.Helper()
		requestNonce, err := client.RequestNonce(ctx, controller)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := client.Begin(auth, candidate)
		if err != nil {
			t.Fatal(err)
		}
		backend.Commit()
		receipt, err := backend.TransactionReceipt(ctx, tx.Hash())
		if err != nil || receipt.Status == 0 {
			t.Fatalf("concurrent begin receipt status %v, error %v", receipt, err)
		}
		id := DeriveRequestID(config.Address, chainID, controller, requestNonce)
		pending, err := client.Request(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		candidateStatement := EnrollmentStatement{
			RequestID: id, DID: candidate.DID, Controller: controller,
			WorkKeyHash: candidate.WorkKeyHash, VRFKeyHash: candidate.VRFKeyHash,
			ProfileHash: candidate.ProfileHash, DeviceNullifier: candidate.DeviceNullifier,
			PolicyDigest: policyDigest, EvidenceHash: candidate.EvidenceHash,
			ValidatorEpoch: pending.ValidatorEpoch, Deadline: pending.Deadline,
		}
		candidateDigest := ApprovalDigest(chainID, config.Address, candidateStatement)
		one, _ := crypto.Sign(candidateDigest[:], validatorOne)
		two, _ := crypto.Sign(candidateDigest[:], validatorTwo)
		return id, [][]byte{one, two}
	}
	raceOneID, raceOneApprovals := beginAndApprove(raceOne)
	raceTwoID, raceTwoApprovals := beginAndApprove(raceTwo)
	tx, err := client.Finalize(auth, raceOneID, raceOne, raceOneApprovals)
	if err != nil {
		t.Fatal(err)
	}
	backend.Commit()
	receipt, err = backend.TransactionReceipt(ctx, tx.Hash())
	if err != nil || receipt.Status == 0 {
		t.Fatalf("first concurrent finalization status %v, error %v", receipt, err)
	}
	if _, err := client.Finalize(auth, raceTwoID, raceTwo, raceTwoApprovals); err == nil {
		t.Fatal("second pending enrollment consumed an already-used device nullifier")
	} else if !strings.Contains(err.Error(), "DID already registered") {
		t.Fatalf("second pending enrollment failed for the wrong reason: %v", err)
	}

	producerNullifier := crypto.Keccak256Hash([]byte("producer enrollment nullifier"))
	producerEvidenceBundle := []byte("canonical producer evidence bundle")
	producerEnrollment := EnrollmentData{
		DID:             DeriveDID(chainID, config.Address, producerNullifier),
		WorkKeyHash:     crypto.Keccak256Hash([]byte("producer work")),
		VRFKeyHash:      crypto.Keccak256Hash([]byte("producer vrf")),
		ProfileHash:     crypto.Keccak256Hash([]byte("producer profile")),
		DeviceNullifier: producerNullifier,
		EvidenceHash:    crypto.Keccak256Hash(producerEvidenceBundle),
	}
	nonce, err = client.RequestNonce(ctx, controller)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = client.BeginProducer(auth, producerEnrollment, producerEvidenceBundle)
	if err != nil {
		t.Fatal(err)
	}
	backend.Commit()
	receipt, err = backend.TransactionReceipt(ctx, transaction.Hash())
	if err != nil || receipt.Status == 0 {
		t.Fatalf("producer begin receipt status %v, error %v", receipt, err)
	}
	producerRequestID := DeriveRequestID(config.Address, chainID, controller, nonce)
	producerRequest, err := client.ProducerRequest(ctx, producerRequestID)
	if err != nil {
		t.Fatal(err)
	}
	if producerRequest.Threshold != config.ProducerThreshold || producerRequest.LastSlot-producerRequest.FirstSlot+1 != uint64(config.ProducerSlotCount) {
		t.Fatalf("unexpected producer request: %+v", producerRequest)
	}
	request, err = client.Request(ctx, producerRequestID)
	if err != nil {
		t.Fatal(err)
	}
	producerStatement := ProducerEnrollmentStatement{
		RequestID: producerRequestID, Identity: producerEnrollment.DID, Controller: controller,
		WorkKeyHash: producerEnrollment.WorkKeyHash, VRFKeyHash: producerEnrollment.VRFKeyHash,
		ProfileHash: producerEnrollment.ProfileHash, DeviceNullifier: producerEnrollment.DeviceNullifier,
		PolicyDigest: config.ProducerPolicyDigest, EvidenceHash: producerEnrollment.EvidenceHash,
		FirstSlot: producerRequest.FirstSlot, LastSlot: producerRequest.LastSlot,
		ResponseDeadline: producerRequest.ResponseDeadline,
	}
	if producerStatement.StructHash() != request.StatementHash {
		t.Fatal("Go producer statement hash differs from Solidity request")
	}
	credentialHash, err := CredentialHash([]byte("credential"), []byte("encrypted secret"))
	if err != nil {
		t.Fatal(err)
	}
	secret := crypto.Keccak256Hash([]byte("activated secret"))
	producer := validators[0]
	goCommitment := ProducerChallengeCommitment(chainID, config.Address, producerRequestID, request.StatementHash, producerRequest.FirstSlot, producer, credentialHash, secret)
	contractCommitment, err := client.ProducerChallengeCommitment(ctx, producerRequestID, request.StatementHash, producerRequest.FirstSlot, producer, credentialHash, secret)
	if err != nil || contractCommitment != goCommitment {
		t.Fatalf("producer commitment mismatch: Go %s, contract %s, error %v", goCommitment, contractCommitment, err)
	}
	goChallengeDigest := ProducerChallengeDigest(chainID, config.Address, producerRequestID, producerRequest.FirstSlot, producer, credentialHash, goCommitment)
	contractChallengeDigest, err := client.ProducerChallengeDigest(ctx, producerRequestID, producerRequest.FirstSlot, producer, credentialHash, goCommitment)
	if err != nil || contractChallengeDigest != goChallengeDigest {
		t.Fatalf("producer challenge digest mismatch: Go %s, contract %s, error %v", goChallengeDigest, contractChallengeDigest, err)
	}
	goCertifyChallenge := ProducerCertifyChallenge(chainID, config.Address, producerRequestID, producerRequest.FirstSlot, goCommitment)
	contractCertifyChallenge, err := client.ProducerCertifyChallenge(ctx, producerRequestID, producerRequest.FirstSlot, goCommitment)
	if err != nil || contractCertifyChallenge != goCertifyChallenge {
		t.Fatalf("producer certify challenge mismatch: Go %s, contract %s, error %v", goCertifyChallenge, contractCertifyChallenge, err)
	}
	evidenceHash := crypto.Keccak256Hash([]byte("slot evidence"))
	goApprovalDigest := ProducerApprovalDigest(chainID, config.Address, producerRequestID, producerRequest.FirstSlot, goCommitment, evidenceHash, producerEnrollment.DID, producerRequest.ResponseDeadline)
	contractApprovalDigest, err := client.ProducerApprovalDigest(ctx, producerRequestID, producerRequest.FirstSlot, goCommitment, evidenceHash, producerEnrollment.DID, producerRequest.ResponseDeadline)
	if err != nil || contractApprovalDigest != goApprovalDigest {
		t.Fatalf("producer approval digest mismatch: Go %s, contract %s, error %v", goApprovalDigest, contractApprovalDigest, err)
	}
}
