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
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/log"
	"github.com/cryptoecc/WorldLand/params"
)

// mockChainReader is a minimal consensus.ChainHeaderReader for unit testing.
type mockChainReader struct {
	cfg     *params.ChainConfig
	headers map[common.Hash]*types.Header
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

func TestWIP6MessageFormats(t *testing.T) {
	chainID := make([]byte, 32)
	parentHash := bytes.Repeat([]byte{0x11}, 32)
	sealHash := bytes.Repeat([]byte{0x22}, 32)
	sigma := bytes.Repeat([]byte{0x33}, 65)
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

	sigMsg := make([]byte, 48)
	copy(sigMsg[:8], "VCT_MINE")
	copy(sigMsg[8:40], sealHash)
	binary.LittleEndian.PutUint64(sigMsg[40:48], nonce)
	if got, want := computeMiningSigMsgVCT(sealHash, nonce), crypto.Keccak256(sigMsg); !bytes.Equal(got, want) {
		t.Fatalf("mining sig msg mismatch: got %x want %x", got, want)
	}

	seedMsg := make([]byte, 50+len(sigma))
	copy(seedMsg[:10], "VCT_ECCPOW")
	copy(seedMsg[10:42], sealHash)
	binary.LittleEndian.PutUint64(seedMsg[42:50], nonce)
	copy(seedMsg[50:], sigma)
	if got, want := computePowSeedVCT(sealHash, nonce, sigma), crypto.Keccak256(seedMsg); !bytes.Equal(got, want) {
		t.Fatalf("pow seed mismatch: got %x want %x", got, want)
	}

	legacyMsg := make([]byte, 40)
	copy(legacyMsg[:32], sealHash)
	binary.LittleEndian.PutUint64(legacyMsg[32:40], nonce)
	if got := computeLegacyPowSeed(sealHash, nonce); !bytes.Equal(got, legacyMsg) {
		t.Fatalf("legacy pow seed mismatch: got %x want %x", got, legacyMsg)
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

	if TimeoutEnd != 70 {
		t.Fatalf("TimeoutEnd = %d, want 70", TimeoutEnd)
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
		t.Fatalf("difficulty changed during threshold bootstrap: got %v want %v", diff, vctParent.Difficulty)
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
	sigma, err := crypto.Sign(computeMiningSigMsgVCT(sealHash, nonce), prv)
	if err != nil {
		t.Fatalf("crypto.Sign: %v", err)
	}
	header.VRFSignature = sigma
	header.Nonce = types.EncodeNonce(nonce)

	if err := ecc.verifyMiningSig(header, sealHash, true); err != nil {
		t.Fatalf("verifyMiningSig: %v", err)
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
