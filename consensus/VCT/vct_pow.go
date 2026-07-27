//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import "github.com/cryptoecc/WorldLand/core/types"

// VCTVerifyOptimizedDecoding verifies a pre-Seoul ECCPoW block where the seed
// is the VCT-specific powSeed =
// Keccak256(VCT_ECCPOW || sealHash || verifiedVRFOutput || nonce || signature).
// The raw LDPC verify function is left unchanged; this wrapper is the VCT entry point.
func VCTVerifyOptimizedDecoding(header *types.Header, powSeed []byte) (bool, []int, []int, []byte) {
	return VerifyOptimizedDecoding(header, powSeed)
}

// VCTVerifyOptimizedDecodingSeoul is the Seoul-era equivalent of VCTVerifyOptimizedDecoding.
func VCTVerifyOptimizedDecodingSeoul(header *types.Header, powSeed []byte) (bool, []int, []int, []byte) {
	return VerifyOptimizedDecodingSeoul(header, powSeed)
}
