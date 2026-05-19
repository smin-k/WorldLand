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

func (m *mockChainReader) Config() *params.ChainConfig { return m.cfg }
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

func TestWIP6ProgressiveTimeoutSortition(t *testing.T) {
	var output [32]byte

	output[0] = SortitionBase - 1
	if !SortitionEligible(output, 0) {
		t.Fatal("base-eligible output rejected")
	}

	output[0] = SortitionBase
	if SortitionEligible(output, TimeoutStart-1) {
		t.Fatal("non-base output accepted before timeout start")
	}

	delay := SortitionSubmitDelay(output[0])
	if delay < TimeoutStart || delay > TimeoutEnd {
		t.Fatalf("submit delay out of range: %d", delay)
	}
	if !SortitionEligible(output, delay) {
		t.Fatalf("output not eligible at computed delay %d", delay)
	}

	output[0] = 0xff
	if !SortitionEligible(output, TimeoutEnd) {
		t.Fatal("timeout end should accept all outputs")
	}
}

// TestVCTVRFFullPipeline exercises the complete VRF pipeline in WIP-6 mode:
//   SetVRFKey → EnsureVRFKeys → IsEligibleForBlock → verifyVRFProof → verifyMiningSig
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
		Difficulty: big.NewInt(0x3ff),
		Time:       1700000000,
	}
	chain := &mockChainReader{
		cfg:     cfg,
		headers: map[common.Hash]*types.Header{parent.Hash(): parent},
	}

	// 4. Generate VRF proof through the real IsEligibleForBlock path.
	parentHash := parent.Hash()
	_, proof, err := ecc.IsEligibleForBlock(chain, blockNum, parentHash)
	if err != nil {
		t.Fatalf("IsEligibleForBlock: %v", err)
	}

	// 5. Build the block header with VRF fields.
	//    Raw deltaT = TimeoutEnd + VCTFutureTolerance → effectiveDeltaT = TimeoutEnd
	//    → SortitionEligible returns true for any output.
	header := &types.Header{
		ParentHash: parentHash,
		Coinbase:   coinbase,
		Number:     big.NewInt(int64(blockNum)),
		Difficulty: big.NewInt(0x3ff),
		GasLimit:   30000000,
		Time:       parent.Time + TimeoutEnd + VCTFutureTolerance,
		VRFProof:   proof,
	}
	ecc.lock.Lock()
	header.VRFPublicKey = make([]byte, len(ecc.vrfPubKey))
	copy(header.VRFPublicKey, ecc.vrfPubKey)
	ecc.lock.Unlock()

	// 6. verifyVRFProof: checks PubkeyToAddress(VRFPublicKey)==Coinbase,
	//    VRFVerify, and time-dependent sortition threshold.
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
