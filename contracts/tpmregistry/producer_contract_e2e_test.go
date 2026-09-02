package tpmregistry_test

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/consensus/ethash"
	. "github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/core"
	"github.com/cryptoecc/WorldLand/core/rawdb"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/core/vm"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/params"
)

func TestProducerRegistryLifecycleInCoinbaseSlots(t *testing.T) {
	chainID := big.NewInt(1337)
	chainConfig := new(params.ChainConfig)
	*chainConfig = *params.AllEthashProtocolChanges
	chainConfig.ChainID = chainID
	controllerKey, _ := crypto.GenerateKey()
	producerKey, _ := crypto.GenerateKey()
	controller := crypto.PubkeyToAddress(controllerKey.PublicKey)
	producer := crypto.PubkeyToAddress(producerKey.PublicKey)
	registry := DefaultRegistryAddress
	policy := crypto.Keccak256Hash([]byte("producer policy"))
	predeploy := PredeployConfig{
		Address: registry, FixedCollateral: new(big.Int), Governor: controller, RegistrationTTL: 20,
		ProducerSlotCount: 1, ProducerThreshold: 1, ProducerResponseWindow: 5,
		ProducerPolicyDigest: policy,
	}
	code, err := RegistryRuntimeCode()
	if err != nil {
		t.Fatal(err)
	}
	storage, err := PredeployStorage(predeploy)
	if err != nil {
		t.Fatal(err)
	}
	config := &core.Genesis{
		Config: chainConfig,
		Alloc: core.GenesisAlloc{
			controller: {Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)},
			producer:   {Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)},
			registry:   {Code: code, Storage: storage, Balance: new(big.Int)},
		},
		GasLimit: 15_000_000,
	}
	database := rawdb.NewMemoryDatabase()
	genesis := config.MustCommit(database)
	engine := ethash.NewFaker()
	defer engine.Close()
	chain, err := core.NewBlockChain(database, nil, config, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	signer := types.LatestSignerForChainID(chainID)
	gasPrice := big.NewInt(2 * params.InitialBaseFee)

	nullifier := crypto.Keccak256Hash([]byte("physical TPM"))
	identity := DeriveConsensusIdentity(chainID, registry, nullifier)
	evidenceBundle := []byte("canonical public enrollment evidence")
	enrollment := EnrollmentData{
		DID: identity, WorkKeyHash: crypto.Keccak256Hash([]byte("work")),
		VRFKeyHash: crypto.Keccak256Hash([]byte("vrf")), ProfileHash: crypto.Keccak256Hash([]byte("profile")),
		DeviceNullifier: nullifier, EvidenceHash: crypto.Keccak256Hash(evidenceBundle),
	}
	requestID := DeriveRequestID(registry, chainID, controller, new(big.Int))
	beginData, err := PackRegistryCall("beginProducerRegistration", enrollment, evidenceBundle)
	if err != nil {
		t.Fatal(err)
	}
	beginTx := signRegistryTx(t, signer, controllerKey, 0, registry, beginData, gasPrice)
	blocks, receipts := core.GenerateChain(chainConfig, genesis, engine, database, 1, func(_ int, block *core.BlockGen) {
		block.SetCoinbase(producer)
		block.AddTx(beginTx)
	})
	registrationEvent, err := ParseProducerRegistrationEvent(findEventLog(t, receipts[0], ProducerEventTopic("ProducerRegistrationRequested")))
	if err != nil {
		t.Fatal(err)
	}
	if registrationEvent.RequestID != requestID || registrationEvent.Identity != identity ||
		registrationEvent.Controller != controller || registrationEvent.StatementHash == (common.Hash{}) ||
		string(registrationEvent.EvidenceBundle) != string(evidenceBundle) {
		t.Fatalf("unexpected registration event: %+v", registrationEvent)
	}
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatal(err)
	}

	statement := ProducerEnrollmentStatement{
		RequestID: requestID, Identity: identity, Controller: controller,
		WorkKeyHash: enrollment.WorkKeyHash, VRFKeyHash: enrollment.VRFKeyHash,
		ProfileHash: enrollment.ProfileHash, DeviceNullifier: nullifier,
		PolicyDigest: policy, EvidenceHash: enrollment.EvidenceHash,
		FirstSlot: 2, LastSlot: 2, ResponseDeadline: 7,
	}
	credentialBlob := []byte("credential blob")
	encryptedSecret := []byte("encrypted secret")
	credentialHash, err := CredentialHash(credentialBlob, encryptedSecret)
	if err != nil {
		t.Fatal(err)
	}
	secret := crypto.Keccak256Hash([]byte("activated secret"))
	commitment := ProducerChallengeCommitment(
		chainID, registry, requestID, statement.StructHash(), 2, producer, credentialHash, secret,
	)
	challengeDigest := ProducerChallengeDigest(chainID, registry, requestID, 2, producer, credentialHash, commitment)
	challengeSignature, _ := crypto.Sign(challengeDigest[:], producerKey)
	challengeData, err := PackRegistryCall(
		"publishProducerChallenge", requestID, credentialBlob, encryptedSecret, commitment, challengeSignature,
	)
	if err != nil {
		t.Fatal(err)
	}
	challengeTx := signRegistryTx(t, signer, producerKey, 0, registry, challengeData, gasPrice)
	blocks, receipts = core.GenerateChain(chainConfig, blocks[0], engine, database, 1, func(_ int, block *core.BlockGen) {
		block.SetCoinbase(producer)
		block.AddTx(challengeTx)
	})
	challengeEvent, err := ParseProducerChallengeEvent(findEventLog(t, receipts[0], ProducerEventTopic("ProducerChallengePublished")))
	if err != nil {
		t.Fatal(err)
	}
	if challengeEvent.RequestID != requestID || challengeEvent.Slot != 2 || challengeEvent.Producer != producer ||
		challengeEvent.Commitment != commitment || string(challengeEvent.CredentialBlob) != string(credentialBlob) ||
		string(challengeEvent.EncryptedSecret) != string(encryptedSecret) {
		t.Fatalf("unexpected challenge event: %+v", challengeEvent)
	}
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatal(err)
	}

	responseEvidence := []byte("canonical certify evidence")
	responseData, err := PackRegistryCall("submitProducerResponse", requestID, uint64(2), secret, responseEvidence)
	if err != nil {
		t.Fatal(err)
	}
	responseTx := signRegistryTx(t, signer, controllerKey, 1, registry, responseData, gasPrice)
	evidenceHash := crypto.Keccak256Hash(responseEvidence)
	approvalDigest := ProducerApprovalDigest(chainID, registry, requestID, 2, commitment, evidenceHash, identity, 7)
	approvalSignature, _ := crypto.Sign(approvalDigest[:], producerKey)
	approvalData, err := PackRegistryCall("approveProducerSlot", requestID, uint64(2), identity, approvalSignature)
	if err != nil {
		t.Fatal(err)
	}
	approvalTx := signRegistryTx(t, signer, producerKey, 1, registry, approvalData, gasPrice)
	finalizeData, err := PackRegistryCall("finalizeProducerRegistration", requestID, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	finalizeTx := signRegistryTx(t, signer, controllerKey, 2, registry, finalizeData, gasPrice)
	blocks, receipts = core.GenerateChain(chainConfig, blocks[0], engine, database, 1, func(_ int, block *core.BlockGen) {
		block.SetCoinbase(producer)
		block.AddTx(responseTx)
		block.AddTx(approvalTx)
		block.AddTx(finalizeTx)
	})
	for _, receipt := range receipts[0] {
		if receipt.Status == 0 {
			t.Fatalf("dynamic enrollment transaction %s reverted", receipt.TxHash)
		}
	}
	responseEvent, err := ParseProducerResponseEvent(findEventLog(t, receipts[0], ProducerEventTopic("ProducerResponseSubmitted")))
	if err != nil {
		t.Fatal(err)
	}
	if responseEvent.RequestID != requestID || responseEvent.Slot != 2 || responseEvent.EvidenceHash != evidenceHash ||
		string(responseEvent.EvidenceBundle) != string(responseEvidence) {
		t.Fatalf("unexpected response event: %+v", responseEvent)
	}
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatal(err)
	}
}

func findEventLog(t *testing.T, receipts types.Receipts, topic common.Hash) types.Log {
	t.Helper()
	for _, receipt := range receipts {
		for _, entry := range receipt.Logs {
			if len(entry.Topics) != 0 && entry.Topics[0] == topic {
				return *entry
			}
		}
	}
	t.Fatalf("event %s not found", topic)
	return types.Log{}
}

func signRegistryTx(t *testing.T, signer types.Signer, privateKey *ecdsa.PrivateKey, nonce uint64, registry common.Address, data []byte, gasPrice *big.Int) *types.Transaction {
	t.Helper()
	tx, err := types.SignTx(types.NewTransaction(nonce, registry, new(big.Int), 5_000_000, gasPrice, data), signer, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}
