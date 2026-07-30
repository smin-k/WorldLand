//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/consensus/eccpow"
	"github.com/cryptoecc/WorldLand/core/rawdb"
	"github.com/cryptoecc/WorldLand/core/state"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/log"
	"github.com/cryptoecc/WorldLand/params"
)

// mockChainReader is a minimal consensus.ChainHeaderReader for unit testing.
type mockChainReader struct {
	cfg     *params.ChainConfig
	headers map[common.Hash]*types.Header
	blocks  map[common.Hash]*types.Block
	states  map[common.Hash]*state.StateDB
}

func (m *mockChainReader) Config() *params.ChainConfig  { return m.cfg }
func (m *mockChainReader) CurrentHeader() *types.Header { return nil }
func (m *mockChainReader) GetHeader(hash common.Hash, number uint64) *types.Header {
	return m.headers[hash]
}
func (m *mockChainReader) GetHeaderByNumber(number uint64) *types.Header {
	for _, h := range m.headers {
		if h.Number.Uint64() == number {
			return h
		}
	}
	return nil
}
func (m *mockChainReader) GetHeaderByHash(hash common.Hash) *types.Header {
	return m.headers[hash]
}
func (m *mockChainReader) GetTd(hash common.Hash, number uint64) *big.Int { return nil }
func (m *mockChainReader) GetBlock(hash common.Hash, number uint64) *types.Block {
	return m.blocks[hash]
}
func (m *mockChainReader) StateAt(root common.Hash) (*state.StateDB, error) {
	return m.states[root], nil
}

func TestWIP6MessageFormats(t *testing.T) {
	chainID := make([]byte, 32)
	parentHash := bytes.Repeat([]byte{0x11}, 32)
	sealHash := bytes.Repeat([]byte{0x22}, 32)
	var vrfOutput [32]byte
	copy(vrfOutput[:], bytes.Repeat([]byte{0x33}, 32))
	sigma := bytes.Repeat([]byte{0x44}, 65)
	nonce := uint64(0x0102030405060708)
	binary.BigEndian.PutUint64(chainID[24:], 10399)

	vrfMsg := computeVRFMsg(chainID, parentHash, 42)
	if len(vrfMsg) != 79 {
		t.Fatalf("VRF message length = %d, want 79", len(vrfMsg))
	}
	if !bytes.Equal(vrfMsg[:7], []byte("VCT_VRF")) ||
		!bytes.Equal(vrfMsg[7:39], chainID) ||
		!bytes.Equal(vrfMsg[39:71], parentHash) ||
		binary.BigEndian.Uint64(vrfMsg[71:79]) != 42 {
		t.Fatalf("VRF message layout mismatch: %x", vrfMsg)
	}
	otherParent := bytes.Repeat([]byte{0x12}, 32)
	if bytes.Equal(vrfMsg, computeVRFMsg(chainID, otherParent, 42)) {
		t.Fatal("VRF message is reusable across competing parent forks")
	}
	if bytes.Equal(vrfMsg, computeVRFMsg(chainID, parentHash, 43)) {
		t.Fatal("VRF message is reusable across block heights")
	}

	sigMsg := make([]byte, 80)
	copy(sigMsg[:8], "VCT_MINE")
	copy(sigMsg[8:40], sealHash)
	copy(sigMsg[40:72], vrfOutput[:])
	binary.LittleEndian.PutUint64(sigMsg[72:80], nonce)
	if got, want := computeMiningSigMsgVCT(sealHash, vrfOutput, nonce), crypto.Keccak256(sigMsg); !bytes.Equal(got, want) {
		t.Fatalf("mining sig msg mismatch: got %x want %x", got, want)
	}

	seedMsg := make([]byte, 82+len(sigma))
	copy(seedMsg[:10], "VCT_ECCPOW")
	copy(seedMsg[10:42], sealHash)
	copy(seedMsg[42:74], vrfOutput[:])
	binary.LittleEndian.PutUint64(seedMsg[74:82], nonce)
	copy(seedMsg[82:], sigma)
	if got, want := computePowSeedVCT(sealHash, vrfOutput, nonce, sigma), crypto.Keccak256(seedMsg); !bytes.Equal(got, want) {
		t.Fatalf("pow seed mismatch: got %x want %x", got, want)
	}

	legacyMsg := make([]byte, 40)
	copy(legacyMsg[:32], sealHash)
	binary.LittleEndian.PutUint64(legacyMsg[32:40], nonce)
	if got := computeLegacyPowSeed(sealHash, nonce); !bytes.Equal(got, legacyMsg) {
		t.Fatalf("legacy pow seed mismatch: got %x want %x", got, legacyMsg)
	}
}

func TestVCTPowSeedCommitsToVRFOutputAndPerTrialSignatureNotProof(t *testing.T) {
	ecc := &ECC{config: Config{Log: log.Root()}, chainID: big.NewInt(10399)}
	header := &types.Header{
		ParentHash:           common.HexToHash("0x01"),
		Coinbase:             common.HexToAddress("0x1234"),
		Difficulty:           big.NewInt(65536),
		Number:               big.NewInt(100),
		GasLimit:             30000000,
		Time:                 1700000000,
		VRFPublicKey:         bytes.Repeat([]byte{0x02}, 33),
		VRFProof:             bytes.Repeat([]byte{0x11}, 81),
		VRFSignature:         bytes.Repeat([]byte{0x22}, 65),
		EligibilityThreshold: new(big.Int).Set(EligibilityBase),
	}
	sealHash := ecc.SealHash(header)

	proofMutated := types.CopyHeader(header)
	proofMutated.VRFProof = bytes.Repeat([]byte{0x33}, 81)
	if got := ecc.SealHash(proofMutated); got != sealHash {
		t.Fatalf("proof bytes changed semantic seal hash: got %s want %s", got, sealHash)
	}

	var beta1, beta2 [32]byte
	beta1[31] = 1
	beta2[31] = 2
	sigma1 := bytes.Repeat([]byte{0x55}, 65)
	sigma2 := bytes.Repeat([]byte{0x66}, 65)
	const nonce = uint64(7)
	seed1 := computePowSeedVCT(sealHash.Bytes(), beta1, nonce, sigma1)
	if got := computePowSeedVCT(ecc.SealHash(proofMutated).Bytes(), beta1, nonce, sigma1); !bytes.Equal(got, seed1) {
		t.Fatal("proof mutation changed PoW seed")
	}
	if got := computePowSeedVCT(sealHash.Bytes(), beta2, nonce, sigma1); bytes.Equal(got, seed1) {
		t.Fatal("distinct VRF outputs produced the same PoW seed")
	}
	if got := computePowSeedVCT(sealHash.Bytes(), beta1, nonce, sigma2); bytes.Equal(got, seed1) {
		t.Fatal("distinct per-trial signatures produced the same PoW seed")
	}
}

func TestLegacySealHashMatchesECCPoW(t *testing.T) {
	header := &types.Header{
		ParentHash:  common.HexToHash("0x01"),
		UncleHash:   common.HexToHash("0x02"),
		Coinbase:    common.HexToAddress("0x30593e15c458d8cb0fa852d269092f67f26ad719"),
		Root:        common.HexToHash("0x03"),
		TxHash:      common.HexToHash("0x04"),
		ReceiptHash: common.HexToHash("0x05"),
		Difficulty:  big.NewInt(12345),
		Number:      big.NewInt(99),
		GasLimit:    30000000,
		GasUsed:     21000,
		Time:        1700000000,
		Extra:       []byte("seoul"),
		BaseFee:     big.NewInt(params.InitialBaseFee),
	}
	if got, want := legacySealHash(header), eccpow.NewFaker().SealHash(header); got != want {
		t.Fatalf("legacy seal hash mismatch: got %s want %s", got, want)
	}
}

func TestWIP6ProgressiveTimeoutEligibility(t *testing.T) {
	var output [32]byte

	if TimeoutStart != 70 || TimeoutEnd != 100 {
		t.Fatalf("timeout window = (%d,%d), want (70,100)", TimeoutStart, TimeoutEnd)
	}

	output[0] = 0x1f
	if !EligibilityPasses(output, 0) {
		t.Fatal("base-eligible output rejected")
	}

	output[0] = 0x20
	if EligibilityPasses(output, TimeoutStart-1) {
		t.Fatal("non-base output accepted before timeout start")
	}

	delay := EligibilitySubmitDelay(output)
	if delay < TimeoutStart || delay > TimeoutEnd {
		t.Fatalf("submit delay out of range: %d", delay)
	}
	if !EligibilityPasses(output, delay) {
		t.Fatalf("output not eligible at computed delay %d", delay)
	}

	output[0] = 0xff
	if !EligibilityPasses(output, TimeoutEnd) {
		t.Fatal("timeout end should accept all outputs")
	}
}

func TestWIP6EligibilityThresholdUsesIntegerSecondSchedule(t *testing.T) {
	window := TimeoutEnd - TimeoutStart
	previous := new(big.Int).Set(EligibilityBase)
	for second := TimeoutStart; second < TimeoutEnd; second++ {
		threshold := EligibilityThresholdAt(EligibilityBase, second)
		if threshold.Cmp(previous) < 0 {
			t.Fatalf("threshold decreased at second %d", second)
		}

		// The returned value is the exact floor of the integer formulation:
		// threshold^W <= base^(te-d) * denominator^(d-ts) < (threshold+1)^W.
		elapsed := second - TimeoutStart
		remaining := TimeoutEnd - second
		radical := new(big.Int).Exp(EligibilityBase, new(big.Int).SetUint64(remaining), nil)
		radical.Mul(radical, new(big.Int).Exp(EligibilityDenominator, new(big.Int).SetUint64(elapsed), nil))
		if new(big.Int).Exp(threshold, new(big.Int).SetUint64(window), nil).Cmp(radical) > 0 {
			t.Fatalf("threshold at second %d exceeds exact integer root", second)
		}
		next := new(big.Int).Add(threshold, big.NewInt(1))
		if new(big.Int).Exp(next, new(big.Int).SetUint64(window), nil).Cmp(radical) <= 0 {
			t.Fatalf("threshold at second %d is below exact floor root", second)
		}
		previous = threshold
	}

	if got := EligibilityThresholdAt(EligibilityBase, TimeoutStart); got.Cmp(EligibilityBase) != 0 {
		t.Fatalf("threshold at timeout start = %v, want base %v", got, EligibilityBase)
	}
	if got := EligibilityThresholdAt(EligibilityBase, TimeoutEnd); got.Cmp(EligibilityThresholdMax) != 0 {
		t.Fatalf("threshold at timeout end = %v, want max %v", got, EligibilityThresholdMax)
	}
}

func TestWIP6BalanceWeightedVirtualTrials(t *testing.T) {
	one := BalanceWeightedThreshold(EligibilityBase, big.NewInt(1))
	four := BalanceWeightedThreshold(EligibilityBase, big.NewInt(4))
	ten := BalanceWeightedThreshold(EligibilityBase, big.NewInt(10))
	if one.Cmp(EligibilityBase) != 0 {
		t.Fatalf("weight-one threshold = %v, want %v", one, EligibilityBase)
	}
	if !(four.Cmp(one) > 0 && ten.Cmp(four) > 0) {
		t.Fatalf("weighted thresholds are not strictly increasing: one=%v four=%v ten=%v", one, four, ten)
	}
	if got := BalanceWeightedThreshold(EligibilityBase, new(big.Int)); got.Sign() != 0 {
		t.Fatalf("zero weight threshold = %v, want zero", got)
	}

	var output [32]byte
	EligibilityBase.FillBytes(output[:])
	if EligibilityPassesWithWeight(output, EligibilityBase, 0, big.NewInt(1)) {
		t.Fatal("weight one accepted output exactly at the unit threshold")
	}
	if !EligibilityPassesWithWeight(output, EligibilityBase, 0, big.NewInt(4)) {
		t.Fatal("weight four did not accept output below its weighted threshold")
	}
	if delay4, delay1 := EligibilitySubmitDelayWithWeight(output, EligibilityBase, big.NewInt(4)), EligibilitySubmitDelayWithWeight(output, EligibilityBase, big.NewInt(1)); delay4 >= delay1 {
		t.Fatalf("weight four delay %d is not below weight one delay %d", delay4, delay1)
	}
}

func TestWIP6EffectiveDeltaT(t *testing.T) {
	tests := []struct {
		raw  uint64
		want uint64
	}{
		{0, 0},
		{VCTFutureTolerance, 0},
		{VCTFutureTolerance + 1, 1},
		{VCTFutureTolerance + TimeoutStart, TimeoutStart},
		{VCTFutureTolerance + TimeoutEnd, TimeoutEnd},
	}
	for _, tt := range tests {
		if got := EffectiveDeltaT(tt.raw); got != tt.want {
			t.Fatalf("EffectiveDeltaT(%d) = %d, want %d", tt.raw, got, tt.want)
		}
	}
}

func TestWIP6AdaptiveEligibilityThreshold(t *testing.T) {
	cfg := &params.ChainConfig{
		ChainID:  big.NewInt(10399),
		VCTBlock: big.NewInt(100),
		Vct:      &params.VctConfig{},
	}
	ecc := &ECC{config: Config{Log: log.Root()}, chainID: big.NewInt(10399)}

	preForkParent := &types.Header{
		Number:     big.NewInt(99),
		UncleHash:  types.EmptyUncleHash,
		Difficulty: new(big.Int).Mul(MinimumDifficulty, big.NewInt(16)),
		Time:       1000,
	}
	chain := &mockChainReader{
		cfg:     cfg,
		headers: map[common.Hash]*types.Header{preForkParent.Hash(): preForkParent},
	}
	if got := ecc.CalcEligibilityThreshold(chain, preForkParent.Time+1, preForkParent); got.Cmp(EligibilityThresholdMax) != 0 {
		t.Fatalf("first VCT threshold = %v, want %v", got, EligibilityThresholdMax)
	}

	vctParent := &types.Header{
		ParentHash:           preForkParent.Hash(),
		Number:               big.NewInt(100),
		UncleHash:            types.EmptyUncleHash,
		Difficulty:           new(big.Int).Set(preForkParent.Difficulty),
		Time:                 preForkParent.Time + 1,
		EligibilityThreshold: EligibilityThresholdMax,
	}
	chain.headers[vctParent.Hash()] = vctParent

	threshold := ecc.CalcEligibilityThreshold(chain, vctParent.Time+1, vctParent)
	if threshold.Cmp(EligibilityThresholdMax) >= 0 {
		t.Fatalf("fast block did not lower threshold: got %v", threshold)
	}
	if threshold.Cmp(EligibilityBase) < 0 {
		t.Fatalf("threshold below EligibilityBase: got %v, base %v", threshold, EligibilityBase)
	}
	if diff := ecc.CalcDifficulty(chain, vctParent.Time+1, vctParent); diff.Cmp(vctParent.Difficulty) != 0 {
		t.Fatalf("difficulty changed while timing signal was assigned to eligibility: got %v want %v", diff, vctParent.Difficulty)
	}

	slowDiff := ecc.CalcDifficulty(chain, vctParent.Time+uint64(BlockGenerationTime.Int64()*2), vctParent)
	if slowDiff.Cmp(vctParent.Difficulty) >= 0 {
		t.Fatalf("difficulty did not decrease when threshold was already maxed and block was slow: got %v parent %v", slowDiff, vctParent.Difficulty)
	}

	vctParent.EligibilityThreshold = new(big.Int).Set(EligibilityBase)
	if diff := ecc.CalcDifficulty(chain, vctParent.Time+1, vctParent); diff.Cmp(vctParent.Difficulty) <= 0 {
		t.Fatalf("difficulty did not resume after threshold reached base: got %v parent %v", diff, vctParent.Difficulty)
	}
}

func TestWIP8VCTMinimumDifficultyAtFork(t *testing.T) {
	cfg := &params.ChainConfig{
		ChainID:  big.NewInt(10399),
		VCTBlock: big.NewInt(100),
		Vct:      &params.VctConfig{},
	}
	ecc := &ECC{config: Config{Log: log.Root()}, chainID: big.NewInt(10399)}
	parent := &types.Header{
		Number:     big.NewInt(99),
		UncleHash:  types.EmptyUncleHash,
		Difficulty: big.NewInt(1023),
		Time:       1000,
	}
	chain := &mockChainReader{
		cfg:     cfg,
		headers: map[common.Hash]*types.Header{parent.Hash(): parent},
	}
	diff := ecc.CalcDifficulty(chain, parent.Time+1, parent)
	if diff.Cmp(VCTMinimumDifficulty) != 0 {
		t.Fatalf("first VCT difficulty = %v, want minimum %v", diff, VCTMinimumDifficulty)
	}
}

// TestVCTVRFFullPipeline exercises the complete VRF pipeline in WIP-6 mode:
//
//	SetVRFKey -> EnsureVRFKeys -> IsEligibleForBlock -> verifyVRFProof -> verifyMiningSig
func TestVCTVRFFullPipeline(t *testing.T) {
	// 1. Generate a secp256k1 key pair and derive the coinbase address.
	seckey, _ := makeTestKeypair(t)
	prv, err := crypto.ToECDSA(seckey)
	if err != nil {
		t.Fatalf("ToECDSA: %v", err)
	}
	coinbase := crypto.PubkeyToAddress(prv.PublicKey)

	// 2. Build engine with chain ID; no remote sealer needed for pure-crypto paths.
	ecc := &ECC{
		config:  Config{Log: log.Root()},
		chainID: big.NewInt(10399),
	}
	if err := ecc.SetVRFKey(seckey); err != nil {
		t.Fatalf("SetVRFKey: %v", err)
	}
	if err := ecc.EnsureVRFKeys(coinbase); err != nil {
		t.Fatalf("EnsureVRFKeys: %v", err)
	}

	// 3. Mock chain: VCT active from block 0.
	cfg := &params.ChainConfig{
		ChainID:  big.NewInt(10399),
		VCTBlock: big.NewInt(0),
		Vct:      &params.VctConfig{},
	}
	const blockNum = uint64(200)
	parent := &types.Header{
		Number:     big.NewInt(int64(blockNum - 1)),
		Difficulty: big.NewInt(0x10000),
		Time:       1700000000,
	}
	chain := &mockChainReader{
		cfg:     cfg,
		headers: map[common.Hash]*types.Header{parent.Hash(): parent},
	}

	// 4. Generate VRF proof through the real IsEligibleForBlock path.
	parentHash := parent.Hash()
	_, proof, err := ecc.IsEligibleForBlock(chain, blockNum, parentHash, EligibilityThresholdMax)
	if err != nil {
		t.Fatalf("IsEligibleForBlock: %v", err)
	}

	// 5. Build the block header with VRF fields.
	//    Effective deltaT = TimeoutEnd, so EligibilityPasses returns true for any output.
	header := &types.Header{
		ParentHash:           parentHash,
		Coinbase:             coinbase,
		Number:               big.NewInt(int64(blockNum)),
		Difficulty:           big.NewInt(0x10000),
		GasLimit:             30000000,
		Time:                 parent.Time + VCTFutureTolerance + TimeoutEnd,
		VRFProof:             proof,
		EligibilityThreshold: EligibilityThresholdMax,
	}
	ecc.lock.Lock()
	header.VRFPublicKey = make([]byte, len(ecc.vrfPubKey))
	copy(header.VRFPublicKey, ecc.vrfPubKey)
	ecc.lock.Unlock()

	// 6. verifyVRFProof: checks PubkeyToAddress(VRFPublicKey)==Coinbase,
	//    VRFVerify, and time-dependent eligibility threshold.
	if err := ecc.verifyVRFProof(chain, header, parent); err != nil {
		t.Fatalf("verifyVRFProof: %v", err)
	}

	// 7. Per-nonce mining signature: sign with the same key, embed, then verify.
	sealHash := ecc.SealHash(header).Bytes()
	const nonce = uint64(0xCAFEBABE12345678)
	msg := computeVRFMsg(ecc.chainIDBytes(), header.ParentHash.Bytes(), header.Number.Uint64())
	vrfOutput, err := VRFVerify(header.VRFPublicKey, header.VRFProof, msg)
	if err != nil {
		t.Fatalf("VRFVerify: %v", err)
	}
	sigma, err := crypto.Sign(computeMiningSigMsgVCT(sealHash, vrfOutput, nonce), prv)
	if err != nil {
		t.Fatalf("crypto.Sign: %v", err)
	}
	header.VRFSignature = sigma
	header.Nonce = types.EncodeNonce(nonce)

	if err := ecc.verifyMiningSig(header, sealHash, true); err != nil {
		t.Fatalf("verifyMiningSig: %v", err)
	}

	// Toggling the recovery bit and replacing s with N-s yields the standard
	// ECDSA malleation. Consensus must reject this high-s representation so a
	// published authorization cannot be turned into a second work seed.
	malleated := types.CopyHeader(header)
	malleated.VRFSignature = append([]byte(nil), header.VRFSignature...)
	sValue := new(big.Int).SetBytes(malleated.VRFSignature[32:64])
	sValue.Sub(crypto.S256().Params().N, sValue)
	copy(malleated.VRFSignature[32:64], sValue.FillBytes(make([]byte, 32)))
	malleated.VRFSignature[64] ^= 1
	if err := ecc.verifyMiningSig(malleated, sealHash, true); err == nil {
		t.Fatal("malleated high-s mining signature accepted")
	}
	t.Logf("VCT full pipeline OK: coinbase=%s VRFproof=%d bytes", coinbase.Hex(), len(proof))
}

func TestWIP6MinEligibleBalanceAt(t *testing.T) {
	cfg := &params.VctConfig{
		MinEligibleBalance: big.NewInt(10),
		S0ForkBlock:        big.NewInt(5),
		S0ForkBalance:      big.NewInt(3),
	}
	if got := cfg.MinEligibleBalanceAt(big.NewInt(4)); got.Cmp(big.NewInt(10)) != 0 {
		t.Fatalf("pre-fork S0 = %v, want 10", got)
	}
	if got := cfg.MinEligibleBalanceAt(big.NewInt(5)); got.Cmp(big.NewInt(3)) != 0 {
		t.Fatalf("fork S0 = %v, want 3", got)
	}
}

func TestWIP6ProposerEligibilityActivationBoundary(t *testing.T) {
	const activation = uint64(10)
	coinbase := common.HexToAddress("0x1234")
	chain := &mockChainReader{
		cfg: &params.ChainConfig{
			VCTBlock: big.NewInt(int64(activation)),
			Vct: &params.VctConfig{
				MinEligibleBalance: big.NewInt(10),
			},
		},
		headers: make(map[common.Hash]*types.Header),
	}
	statedb, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	ecc := New(Config{}, nil, false)

	// Balance-weighted eligibility is not a consensus rule before VCTBlock.
	preFork := &types.Header{Number: new(big.Int).SetUint64(activation - 1), Coinbase: coinbase}
	if err := ecc.VerifyProposerEligibility(chain, preFork, nil, statedb); err != nil {
		t.Fatalf("pre-fork proposer rejected: %v", err)
	}

	// It activates at VCTBlock itself, not one block later.
	atFork := &types.Header{Number: new(big.Int).SetUint64(activation), Coinbase: coinbase}
	if err := ecc.VerifyProposerEligibility(chain, atFork, nil, statedb); err == nil {
		t.Fatal("underfunded proposer accepted at VCTBlock")
	}

	statedb.AddBalance(coinbase, big.NewInt(10))
	if err := ecc.VerifyProposerEligibility(chain, atFork, nil, statedb); err != nil {
		t.Fatalf("funded proposer rejected at VCTBlock: %v", err)
	}
}

func TestWIP6PreForkVCTFieldsMustBeAbsent(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*types.Header)
	}{
		{"public key", func(h *types.Header) { h.VRFPublicKey = []byte{} }},
		{"proof", func(h *types.Header) { h.VRFProof = []byte{} }},
		{"signature", func(h *types.Header) { h.VRFSignature = []byte{} }},
		{"threshold", func(h *types.Header) { h.EligibilityThreshold = new(big.Int) }},
	}
	if err := verifyPreVCTFields(&types.Header{}); err != nil {
		t.Fatalf("absent VCT fields rejected: %v", err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header := new(types.Header)
			test.mutate(header)
			if err := verifyPreVCTFields(header); err == nil {
				t.Fatal("explicitly present pre-VCT field accepted")
			}
		})
	}
}

func TestWIP6UncleEligibilityUsesOwnParentState(t *testing.T) {
	const activation = uint64(10)
	coinbase := common.HexToAddress("0x1234")
	parentRoot := common.HexToHash("0x01")
	parent := &types.Header{Number: new(big.Int).SetUint64(activation - 1), Root: parentRoot}
	uncle := &types.Header{Number: new(big.Int).SetUint64(activation), Coinbase: coinbase}
	parentState, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	chain := &mockChainReader{
		cfg: &params.ChainConfig{
			VCTBlock: big.NewInt(int64(activation)),
			Vct: &params.VctConfig{
				MinEligibleBalance: big.NewInt(10),
			},
		},
		headers: make(map[common.Hash]*types.Header),
		blocks:  make(map[common.Hash]*types.Block),
		states:  map[common.Hash]*state.StateDB{parentRoot: parentState},
	}
	ecc := New(Config{}, nil, false)

	if err := ecc.verifyUncleProposerEligibility(chain, uncle, parent); err == nil {
		t.Fatal("underfunded VCT uncle accepted")
	}
	parentState.AddBalance(coinbase, big.NewInt(10))
	if err := ecc.verifyUncleProposerEligibility(chain, uncle, parent); err != nil {
		t.Fatalf("funded VCT uncle rejected: %v", err)
	}

	// The containing block may be post-fork, but a pre-fork uncle keeps legacy
	// eligibility semantics and does not require an S0 balance.
	legacyUncle := &types.Header{Number: new(big.Int).SetUint64(activation - 1), Coinbase: common.HexToAddress("0x9999")}
	if err := ecc.verifyUncleProposerEligibility(chain, legacyUncle, parent); err != nil {
		t.Fatalf("pre-fork uncle rejected by S0 gate: %v", err)
	}
}
