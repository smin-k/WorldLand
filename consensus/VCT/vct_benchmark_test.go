//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
)

var (
	benchmarkSignature []byte
	benchmarkWord      []int
	benchmarkThreshold *big.Int
)

func benchmarkVCTInputs(b *testing.B) (*types.Header, []byte, [32]byte, *ecdsa.PrivateKey) {
	b.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	header := &types.Header{
		ParentHash: common.HexToHash("0x01"),
		Difficulty: new(big.Int).Set(MinimumDifficulty),
	}
	sealHash := crypto.Keccak256([]byte("vct-benchmark-seal-hash"))
	var beta [32]byte
	copy(beta[:], crypto.Keccak256([]byte("vct-benchmark-vrf-output")))
	return header, sealHash, beta, key
}

func BenchmarkVCTPerAttemptECDSA(b *testing.B) {
	_, sealHash, beta, key := benchmarkVCTInputs(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := crypto.Sign(computeMiningSigMsgVCT(sealHash, beta, uint64(i)), key)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkSignature = sig
	}
}

func BenchmarkVCTECCVCCAttempt(b *testing.B) {
	header, sealHash, beta, key := benchmarkVCTInputs(b)
	sig, err := crypto.Sign(computeMiningSigMsgVCT(sealHash, beta, 0), key)
	if err != nil {
		b.Fatal(err)
	}
	parameters, _ := setParameters(header)
	H := generateH(parameters)
	colInRow, rowInCol := generateQ(parameters, H)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		powSeed := computePowSeedVCT(sealHash, beta, uint64(i), sig)
		digest := crypto.Keccak512(powSeed)
		hv := generateHv(parameters, digest)
		_, outputWord, _ := OptimizedDecoding(parameters, hv, H, rowInCol, colInRow)
		MakeDecision(header, colInRow, outputWord)
		benchmarkWord = outputWord
	}
}

func BenchmarkVCTSignedECCVCCAttempt(b *testing.B) {
	header, sealHash, beta, key := benchmarkVCTInputs(b)
	parameters, _ := setParameters(header)
	H := generateH(parameters)
	colInRow, rowInCol := generateQ(parameters, H)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := crypto.Sign(computeMiningSigMsgVCT(sealHash, beta, uint64(i)), key)
		if err != nil {
			b.Fatal(err)
		}
		powSeed := computePowSeedVCT(sealHash, beta, uint64(i), sig)
		digest := crypto.Keccak512(powSeed)
		hv := generateHv(parameters, digest)
		_, outputWord, _ := OptimizedDecoding(parameters, hv, H, rowInCol, colInRow)
		MakeDecision(header, colInRow, outputWord)
		benchmarkSignature = sig
		benchmarkWord = outputWord
	}
}

func BenchmarkVCTIntegerEligibilityThreshold(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Exercise an interior second; endpoints return without a root.
		benchmarkThreshold = EligibilityThresholdAt(EligibilityBase, TimeoutStart+27)
	}
}
