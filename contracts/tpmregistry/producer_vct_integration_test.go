//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package tpmregistry_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"

	"github.com/cryptoecc/WorldLand/common"
	vct "github.com/cryptoecc/WorldLand/consensus/VCT"
	"github.com/cryptoecc/WorldLand/consensus/ethash"
	registry "github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/core"
	"github.com/cryptoecc/WorldLand/core/rawdb"
	"github.com/cryptoecc/WorldLand/core/state"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/core/vm"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/params"
)

// This tests real registry bytecode/state transitions and the production VCT
// proposer gate. The transaction chain uses fake PoW to keep it deterministic;
// producer approvals stand in for off-chain TPM evidence verification. It does
// not perform physical TPM enrollment, ECCPoW mining, or a network experiment.
func TestDynamicProducerRegistrationReachesVCTEligibility(t *testing.T) {
	const seedDelay, activationDelay = uint64(2), uint64(3)
	chainID := big.NewInt(1337)
	cfg := new(params.ChainConfig)
	*cfg = *params.AllEthashProtocolChanges
	cfg.ChainID = chainID
	cfg.VCTBlock, cfg.TPMGatedBlock = big.NewInt(1), big.NewInt(1)
	cfg.Vct = &params.VctConfig{SeedDelay: seedDelay, InitialEligibilityThreshold: big.NewInt(256)}
	if err := cfg.CheckTPMActivationDelay(activationDelay); err != nil {
		t.Fatal(err)
	}
	keyFor := func(scalar byte) *ecdsa.PrivateKey {
		secret := make([]byte, 32)
		secret[31] = scalar
		key, err := crypto.ToECDSA(secret)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	controllerKey := keyFor(1)
	controller := crypto.PubkeyToAddress(controllerKey.PublicKey)
	producerKeys := []*ecdsa.PrivateKey{keyFor(2), keyFor(3), keyFor(4)}
	producers := make([]common.Address, len(producerKeys))
	policy := crypto.Keccak256Hash([]byte("test-only producer approval policy"))
	predeploy := registry.PredeployConfig{
		Address: registry.DefaultRegistryAddress, FixedCollateral: new(big.Int), Governor: controller,
		RegistrationTTL: 20, ActivationDelay: activationDelay,
		ProducerSlotCount: 3, ProducerThreshold: 3, ProducerResponseWindow: 10,
		ProducerPolicyDigest: policy,
	}
	code, err := registry.RegistryRuntimeCode()
	if err != nil {
		t.Fatal(err)
	}
	storage, err := registry.PredeployStorage(predeploy)
	if err != nil {
		t.Fatal(err)
	}
	funding := new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)
	alloc := core.GenesisAlloc{
		controller:        {Balance: new(big.Int).Set(funding)},
		predeploy.Address: {Code: code, Storage: storage, Balance: new(big.Int)},
	}
	for i, key := range producerKeys {
		producers[i] = crypto.PubkeyToAddress(key.PublicKey)
		alloc[producers[i]] = core.GenesisAccount{Balance: new(big.Int).Set(funding)}
	}
	genesisSpec := &core.Genesis{Config: cfg, Alloc: alloc, GasLimit: 15_000_000}
	database := rawdb.NewMemoryDatabase()
	genesis := genesisSpec.MustCommit(database)
	txEngine := ethash.NewFaker()
	defer txEngine.Close()
	chain, err := core.NewBlockChain(database, nil, genesisSpec, nil, txEngine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	parent := genesis
	appendBlock := func(coinbase common.Address, transactions []*types.Transaction, statuses []uint64) *types.Block {
		t.Helper()
		blocks, receipts := core.GenerateChain(cfg, parent, txEngine, database, 1, func(_ int, block *core.BlockGen) {
			block.SetCoinbase(coinbase)
			for _, tx := range transactions {
				block.AddTx(tx)
			}
		})
		if len(receipts[0]) != len(statuses) {
			t.Fatalf("receipt count %d, want %d", len(receipts[0]), len(statuses))
		}
		for i, receipt := range receipts[0] {
			if receipt.Status != statuses[i] {
				t.Fatalf("height %d transaction %d status %d, want %d", blocks[0].NumberU64(), i, receipt.Status, statuses[i])
			}
		}
		if _, err := chain.InsertChain(blocks); err != nil {
			t.Fatal(err)
		}
		parent = blocks[0]
		return parent
	}
	signer := types.LatestSignerForChainID(chainID)
	gasPrice := big.NewInt(2 * params.InitialBaseFee)
	transaction := func(key *ecdsa.PrivateKey, nonce uint64, method string, args ...interface{}) *types.Transaction {
		t.Helper()
		data, err := registry.PackRegistryCall(method, args...)
		if err != nil {
			t.Fatal(err)
		}
		return signRegistryTx(t, signer, key, nonce, predeploy.Address, data, gasPrice)
	}
	vrfPublic := crypto.CompressPubkey(&controllerKey.PublicKey)
	vrfHash, err := registry.VRFKeyHash(crypto.FromECDSAPub(&controllerKey.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	x, y := elliptic.P256().ScalarBaseMult([]byte{5})
	workPublic := elliptic.Marshal(elliptic.P256(), x, y)
	nullifier := crypto.Keccak256Hash([]byte("test-only attested device fixture"))
	identity := registry.DeriveConsensusIdentity(chainID, predeploy.Address, nullifier)
	evidence := []byte("test-only attestation bundle; no physical TPM")
	enrollment := registry.EnrollmentData{
		DID: identity, WorkKeyHash: crypto.Keccak256Hash(workPublic), VRFKeyHash: vrfHash,
		ProfileHash: crypto.Keccak256Hash([]byte("integration profile")), DeviceNullifier: nullifier,
		EvidenceHash: crypto.Keccak256Hash(evidence),
	}
	requestID := registry.DeriveRequestID(predeploy.Address, chainID, controller, new(big.Int))
	appendBlock(producers[0], []*types.Transaction{transaction(controllerKey, 0, "beginProducerRegistration", enrollment, evidence)}, []uint64{1})
	statement := registry.ProducerEnrollmentStatement{
		RequestID: requestID, Identity: identity, Controller: controller,
		WorkKeyHash: enrollment.WorkKeyHash, VRFKeyHash: enrollment.VRFKeyHash,
		ProfileHash: enrollment.ProfileHash, DeviceNullifier: nullifier,
		PolicyDigest: policy, EvidenceHash: enrollment.EvidenceHash,
		FirstSlot: 2, LastSlot: 4, ResponseDeadline: 14,
	}
	secrets, commitments := make([]common.Hash, 3), make([]common.Hash, 3)
	for i, producer := range producers {
		slot := uint64(i + 2)
		credential, encrypted := []byte{byte(i + 1), 1}, []byte{byte(i + 1), 2}
		credentialHash, err := registry.CredentialHash(credential, encrypted)
		if err != nil {
			t.Fatal(err)
		}
		secrets[i] = crypto.Keccak256Hash([]byte{byte(i), 3})
		commitments[i] = registry.ProducerChallengeCommitment(chainID, predeploy.Address, requestID, statement.StructHash(), slot, producer, credentialHash, secrets[i])
		digest := registry.ProducerChallengeDigest(chainID, predeploy.Address, requestID, slot, producer, credentialHash, commitments[i])
		signature, err := crypto.Sign(digest[:], producerKeys[i])
		if err != nil {
			t.Fatal(err)
		}
		appendBlock(producer, []*types.Transaction{transaction(producerKeys[i], 0, "publishProducerChallenge", requestID, credential, encrypted, commitments[i], signature)}, []uint64{1})
	}
	gate := vct.New(vct.Config{PowMode: vct.ModeNormal}, nil, false)
	defer gate.Close()
	if err := gate.SetVRFKey(crypto.FromECDSA(controllerKey)); err != nil {
		t.Fatal(err)
	}
	candidate := func(parent *types.Block) (*types.Header, *state.StateDB) {
		t.Helper()
		header := &types.Header{
			ParentHash: parent.Hash(), Number: new(big.Int).Add(parent.Number(), big.NewInt(1)),
			Time: parent.Time() + vct.TimeoutEnd + vct.VCTFutureTolerance, Coinbase: controller, VRFPublicKey: vrfPublic,
			TPMDID: identity.Bytes(), TPMWorkPublicKey: workPublic,
		}
		if err := gate.Prepare(chain, header); err != nil {
			t.Fatal(err)
		}
		// Use the actual full-timeout stage so eligibility cannot make this
		// registry/state-boundary regression probabilistic.
		_, proof, err := gate.IsEligibleForBlock(chain, header.Number.Uint64(), parent.Hash(), header.EligibilityThreshold)
		if err != nil {
			t.Fatalf("create VRF proof: %v", err)
		}
		header.VRFProof = proof
		// Registration blocks deliberately use fake PoW and no VRF proofs, so
		// production delayedVRFMessage uses their hash fallback. Independently
		// verify the exact branch-local delayed-seed input and height binding.
		height := header.Number.Uint64()
		seedHeight := uint64(0)
		if height > seedDelay {
			seedHeight = height - seedDelay
		}
		seed := chain.GetHeaderByNumber(seedHeight)
		message := make([]byte, 79)
		copy(message, "VCT_VRF")
		chainID.FillBytes(message[7:39])
		copy(message[39:71], seed.Hash().Bytes())
		binary.BigEndian.PutUint64(message[71:], height)
		if _, err := vct.VRFVerify(vrfPublic, proof, message); err != nil {
			t.Fatalf("genuine candidate VRF verification: %v", err)
		}
		wrongHeight := append([]byte(nil), message...)
		wrongHeight[78] ^= 1
		if _, err := vct.VRFVerify(vrfPublic, proof, wrongHeight); err == nil {
			t.Fatal("candidate VRF proof was replayable at another height")
		}
		st, err := chain.StateAt(parent.Root())
		if err != nil {
			t.Fatal(err)
		}
		return header, st
	}
	assertInactive := func(parent *types.Block) {
		t.Helper()
		header, st := candidate(parent)
		if err := gate.VerifyProposerEligibility(chain, header, parent.Header(), st); err == nil || !strings.Contains(err.Error(), "not active") {
			t.Fatalf("height %d accepted inactive registration or failed for wrong reason: %v", header.Number.Uint64(), err)
		}
	}
	assertInactive(parent) // height 5: all challenges, but no finalized record.
	var completion []*types.Transaction
	var statuses []uint64
	controllerNonce := uint64(1)
	for i := range producers {
		slot := uint64(i + 2)
		response := []byte{byte(i), 4}
		completion = append(completion, transaction(controllerKey, controllerNonce, "submitProducerResponse", requestID, slot, secrets[i], response))
		controllerNonce++
		digest := registry.ProducerApprovalDigest(chainID, predeploy.Address, requestID, slot, commitments[i], crypto.Keccak256Hash(response), identity, statement.ResponseDeadline)
		signature, err := crypto.Sign(digest[:], producerKeys[i])
		if err != nil {
			t.Fatal(err)
		}
		completion = append(completion, transaction(producerKeys[i], 1, "approveProducerSlot", requestID, slot, identity, signature))
		statuses = append(statuses, 1, 1)
		if i == 1 {
			completion = append(completion, transaction(controllerKey, controllerNonce, "finalizeProducerRegistration", requestID, enrollment))
			controllerNonce++
			statuses = append(statuses, 0) // two approvals cannot satisfy 3-of-3.
		}
	}
	completion = append(completion, transaction(controllerKey, controllerNonce, "finalizeProducerRegistration", requestID, enrollment))
	controllerNonce++
	statuses = append(statuses, 1)
	finalized := appendBlock(producers[0], completion, statuses) // height 5
	assertInactive(finalized)                                    // height 6
	appendBlock(producers[0], []*types.Transaction{transaction(controllerKey, controllerNonce, "activate", identity)}, []uint64{0})
	controllerNonce++                                       // activation at height 6 must revert; it still consumes nonce.
	beforeActivation := appendBlock(producers[0], nil, nil) // height 7
	assertInactive(beforeActivation)                        // activation block 8 reads inactive parent 7.
	activated := appendBlock(producers[0], []*types.Transaction{transaction(controllerKey, controllerNonce, "activate", identity)}, []uint64{1})
	if activated.NumberU64() != finalized.NumberU64()+activationDelay {
		t.Fatal("activation height does not respect confirmation delay")
	}
	header, st := candidate(activated) // height 9: parent 8 contains activation.
	if err := gate.VerifyProposerEligibility(chain, header, activated.Header(), st); err != nil {
		t.Fatalf("dynamically registered identity could not enter VCT: %v", err)
	}
	wrongController := types.CopyHeader(header)
	wrongController.Coinbase = producers[0]
	if err := gate.VerifyProposerEligibility(chain, wrongController, activated.Header(), st); err == nil || !strings.Contains(err.Error(), "controller") {
		t.Fatalf("registered identity accepted a different controller: %v", err)
	}
	wrongVRF := types.CopyHeader(header)
	wrongVRF.VRFPublicKey = crypto.CompressPubkey(&producerKeys[0].PublicKey)
	if err := gate.VerifyProposerEligibility(chain, wrongVRF, activated.Header(), st); err == nil || !strings.Contains(err.Error(), "VRF public key") {
		t.Fatalf("registered identity accepted another VRF key: %v", err)
	}
}
