//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/core/rawdb"
	"github.com/cryptoecc/WorldLand/core/state"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/crypto/secp256k1"
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
	"github.com/cryptoecc/WorldLand/log"
	"github.com/cryptoecc/WorldLand/params"
)

var (
	benchmarkTPMGateFixtureOnce sync.Once
	benchmarkTPMGateECC         *ECC
	benchmarkTPMGateChain       *mockChainReader
	benchmarkTPMGateHeader      *types.Header
	benchmarkTPMGateParent      *types.Header
	benchmarkTPMGateParentState *state.StateDB
)

// BenchmarkVCTTPMConsensusGate measures the serial, hot consensus-gate path
// for a valid TPM-gated candidate with an already materialized parent state.
// Candidate construction, state acquisition, body processing, and the ECCPoW
// nonce search are intentionally outside the timed region.
func BenchmarkVCTTPMConsensusGate(b *testing.B) {
	ecc, chain, header, parent, parentState := makeTPMConsensusGateBenchmarkFixture(b)

	// Reject a broken fixture before starting the timer. Header validation and
	// stateful proposer validation are separate calls in the block-import path.
	if err := ecc.VerifyHeader(chain, header, true); err != nil {
		b.Fatalf("fixture header verification: %v", err)
	}
	if err := ecc.VerifyProposerEligibility(chain, header, parent, parentState); err != nil {
		b.Fatalf("fixture proposer verification: %v", err)
	}

	b.ReportAllocs()
	runtime.GC()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ecc.VerifyHeader(chain, header, true); err != nil {
			b.Fatalf("header verification: %v", err)
		}
		if err := ecc.VerifyProposerEligibility(chain, header, parent, parentState); err != nil {
			b.Fatalf("proposer verification: %v", err)
		}
	}
}

func makeTPMConsensusGateBenchmarkFixture(b *testing.B) (*ECC, *mockChainReader, *types.Header, *types.Header, *state.StateDB) {
	b.Helper()
	benchmarkTPMGateFixtureOnce.Do(func() {
		benchmarkTPMGateECC, benchmarkTPMGateChain, benchmarkTPMGateHeader, benchmarkTPMGateParent, benchmarkTPMGateParentState = buildTPMConsensusGateBenchmarkFixture(b)
	})
	return benchmarkTPMGateECC, benchmarkTPMGateChain, benchmarkTPMGateHeader, benchmarkTPMGateParent, benchmarkTPMGateParentState
}

func buildTPMConsensusGateBenchmarkFixture(b *testing.B) (*ECC, *mockChainReader, *types.Header, *types.Header, *state.StateDB) {
	b.Helper()

	chainID := big.NewInt(91510)
	ecc := &ECC{
		config:  Config{PowMode: ModeNormal, Log: log.Root()},
		chainID: new(big.Int).Set(chainID),
	}
	cfg := &params.ChainConfig{
		ChainID:        new(big.Int).Set(chainID),
		SeoulBlock:     big.NewInt(0),
		AnnapurnaBlock: big.NewInt(0),
		VCTBlock:       big.NewInt(1),
		TPMGatedBlock:  big.NewInt(1),
		Vct:            &params.VctConfig{SeedDelay: 1},
	}

	vrfSecret := make([]byte, 32)
	vrfSecret[31] = 1
	vrfPublicKey, err := secp256k1.VRFPubkeyFromSeckey(vrfSecret)
	if err != nil {
		b.Fatalf("derive VRF public key: %v", err)
	}
	accountKey, err := crypto.ToECDSA(vrfSecret)
	if err != nil {
		b.Fatalf("parse VRF account key: %v", err)
	}
	coinbase := crypto.PubkeyToAddress(accountKey.PublicKey)
	deviceNullifier := crypto.Keccak256Hash([]byte("tgpow-validation-benchmark-nullifier"))
	did := tpmregistry.DeriveConsensusIdentity(chainID, TPMRegistryAddress, deviceNullifier)
	profileHash := crypto.Keccak256Hash([]byte("tgpow-validation-benchmark-profile"))
	workKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("generate P-256 work key: %v", err)
	}
	workPublicKey := elliptic.Marshal(elliptic.P256(), workKey.X, workKey.Y)

	// Materialize a registry state that is internally committed to the parent
	// header. Reopening from the committed root avoids benchmarking an
	// unreachable dirty overlay while the untimed preflight warms its reads.
	stateDatabase := state.NewDatabase(rawdb.NewMemoryDatabase())
	registrationState, err := state.New(common.Hash{}, stateDatabase, nil)
	if err != nil {
		b.Fatalf("create registration state: %v", err)
	}
	registrationState.SetState(TPMRegistryAddress, registrationFieldSlot(did, registrationControllerOffset), common.BytesToHash(coinbase.Bytes()))
	registrationState.SetState(TPMRegistryAddress, registrationFieldSlot(did, registrationWorkKeyHashOffset), crypto.Keccak256Hash(workPublicKey))
	registrationState.SetState(TPMRegistryAddress, registrationFieldSlot(did, registrationVRFKeyHashOffset), crypto.Keccak256Hash(vrfPublicKey))
	registrationState.SetState(TPMRegistryAddress, registrationFieldSlot(did, registrationProfileHashOffset), profileHash)
	registrationState.SetState(TPMRegistryAddress, registrationFieldSlot(did, registrationNullifierOffset), deviceNullifier)
	registrationState.SetState(TPMRegistryAddress, registrationFieldSlot(did, registrationActiveOffset), common.BigToHash(big.NewInt(1)))
	parentRoot, err := registrationState.Commit(false)
	if err != nil {
		b.Fatalf("commit registration state: %v", err)
	}
	parentState, err := state.New(parentRoot, stateDatabase, nil)
	if err != nil {
		b.Fatalf("reopen committed parent state: %v", err)
	}

	// Place the measured candidate after a VCT parent so delayedVRFMessage uses
	// the steady-state parent-VRF-output seed, rather than the bootstrap hash
	// fallback. A long-enough elapsed interval makes every valid identity
	// eligible while the protocol floor keeps network difficulty at 65,536.
	elapsed := VCTFutureTolerance + TimeoutEnd
	grandparent := &types.Header{
		UncleHash:  types.EmptyUncleHash,
		Root:       parentRoot,
		Difficulty: new(big.Int).Set(VCTMinimumDifficulty),
		Number:     big.NewInt(0),
		GasLimit:   30_000_000,
		Time:       uint64(time.Now().Unix()) - 2*elapsed - 1,
	}
	// The parent models an already-accepted VCT block. Its VRF proof is valid
	// for the exact bootstrap input, but its unrelated ECCPoW seal is not mined
	// again because only the accepted parent's VRF output enters child checks.
	parent := &types.Header{
		ParentHash:           grandparent.Hash(),
		UncleHash:            types.EmptyUncleHash,
		Coinbase:             coinbase,
		Root:                 parentRoot,
		Difficulty:           new(big.Int).Set(VCTMinimumDifficulty),
		Number:               big.NewInt(1),
		GasLimit:             grandparent.GasLimit,
		Time:                 grandparent.Time + elapsed,
		EligibilityThreshold: new(big.Int).Set(EligibilityThresholdMax),
		VRFPublicKey:         vrfPublicKey,
		VRFSignature:         []byte{},
		TPMDID:               did.Bytes(),
		TPMWorkPublicKey:     workPublicKey,
	}
	parentVRFMessage := computeVRFMsg(ecc.chainIDBytes(), grandparent.Hash().Bytes(), parent.Number.Uint64())
	parent.VRFProof, _, err = VRFProve(vrfSecret, vrfPublicKey, parentVRFMessage)
	if err != nil {
		b.Fatalf("create parent VRF proof: %v", err)
	}
	chain := &mockChainReader{
		cfg: cfg,
		headers: map[common.Hash]*types.Header{
			grandparent.Hash(): grandparent,
			parent.Hash():      parent,
		},
		blocks: make(map[common.Hash]*types.Block),
		states: make(map[common.Hash]*state.StateDB),
	}

	header := &types.Header{
		ParentHash:           parent.Hash(),
		UncleHash:            types.EmptyUncleHash,
		Coinbase:             coinbase,
		Difficulty:           new(big.Int).Set(VCTMinimumDifficulty),
		Number:               big.NewInt(2),
		GasLimit:             parent.GasLimit,
		Time:                 parent.Time + elapsed,
		EligibilityThreshold: new(big.Int).Set(EligibilityThresholdMax),
		VRFPublicKey:         vrfPublicKey,
		VRFSignature:         []byte{},
		TPMDID:               did.Bytes(),
		TPMWorkPublicKey:     workPublicKey,
	}
	vrfMessage, err := ecc.delayedVRFMessage(chain, parent, header.Number.Uint64())
	if err != nil {
		b.Fatalf("derive steady-state child VRF message: %v", err)
	}
	header.VRFProof, _, err = VRFProve(vrfSecret, vrfPublicKey, vrfMessage)
	if err != nil {
		b.Fatalf("create VRF proof: %v", err)
	}

	mineTPMConsensusGateBenchmarkHeader(b, ecc, header, workKey)
	return ecc, chain, header, parent, parentState
}

func mineTPMConsensusGateBenchmarkHeader(b *testing.B, ecc *ECC, header *types.Header, workKey *ecdsa.PrivateKey) {
	b.Helper()

	sealHash := ecc.SealHash(header).Bytes()
	vrfOutput, err := VRFOutputFromProof(header.VRFProof)
	if err != nil {
		b.Fatalf("extract VRF output: %v", err)
	}
	parameters, _ := setParameters_Seoul(header)
	parityCheck := generateH(parameters)
	columnsInRow, rowsInColumn := generateQ(parameters, parityCheck)
	did := common.BytesToHash(header.TPMDID)

	for nonce := uint64(0); ; nonce++ {
		workMessage := computeTPMWorkSigMsg(ecc.chainIDBytes(), sealHash, did, vrfOutput, nonce)
		r, s, signErr := ecdsa.Sign(rand.Reader, workKey, workMessage)
		if signErr != nil {
			b.Fatalf("sign TPM work message: %v", signErr)
		}
		signature := make([]byte, tpmwork.SignatureSize)
		r.FillBytes(signature[:32])
		s.FillBytes(signature[32:])
		signature, signErr = tpmwork.NormalizeSignature(signature)
		if signErr != nil {
			b.Fatalf("normalize TPM signature: %v", signErr)
		}

		digest := crypto.Keccak512(computeTPMPowSeed(workMessage, signature))
		hashVector := generateHv(parameters, digest)
		_, outputWord, _ := OptimizedDecodingSeoul(parameters, hashVector, parityCheck, rowsInColumn, columnsInRow)
		if valid, _ := MakeDecision_Seoul(header, columnsInRow, outputWord); valid {
			header.Nonce = types.EncodeNonce(nonce)
			header.CodeLength = uint64(parameters.n)
			header.MixDigest = common.BytesToHash(digest)
			header.Codeword = packCodeword(outputWord)
			header.TPMWorkSignature = signature
			return
		}
	}
}
