//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/params"
)

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
