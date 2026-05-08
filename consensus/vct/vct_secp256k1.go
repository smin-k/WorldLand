//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"errors"

	secp256k1pkg "github.com/cryptoecc/WorldLand/crypto/secp256k1"
)

var errInvalidVRFProofLen = errors.New("VRF proof must be 81 bytes")

// VRFProve generates an 81-byte secp256k1 VRF proof and the corresponding 32-byte output.
// seckey: 32-byte secp256k1 private key
// pubkey: 33-byte compressed secp256k1 public key
// msg:    arbitrary-length message (e.g. "VCT_VRF|chainId|parentHash|blockNumber")
func VRFProve(seckey, pubkey, msg []byte) (proof []byte, output [32]byte, err error) {
	var proofArr [81]byte
	proofArr, output, err = secp256k1pkg.VRFProve(seckey, pubkey, msg)
	if err != nil {
		return nil, output, err
	}
	proof = make([]byte, 81)
	copy(proof, proofArr[:])
	return proof, output, nil
}

// VRFVerify verifies an 81-byte secp256k1 VRF proof against pubkey and msg.
// Returns the 32-byte VRF output on success.
func VRFVerify(pubkey, proof, msg []byte) ([32]byte, error) {
	if len(proof) != 81 {
		return [32]byte{}, errInvalidVRFProofLen
	}
	var proofArr [81]byte
	copy(proofArr[:], proof)
	return secp256k1pkg.VRFVerify(pubkey, proofArr, msg)
}

// VRFOutputFromProof extracts the 32-byte VRF output from a proof without verifying it.
// Only call after a successful VRFProve or VRFVerify.
func VRFOutputFromProof(proof []byte) ([32]byte, error) {
	if len(proof) != 81 {
		return [32]byte{}, errInvalidVRFProofLen
	}
	var proofArr [81]byte
	copy(proofArr[:], proof)
	return secp256k1pkg.VRFProofToHash(proofArr)
}

// CheckSortition returns true if the VRF proof passes the per-epoch sortition threshold.
// Threshold: first byte of VRF output < 0xA0 (first nibble 0x0–0x9), giving ~62.5% eligibility.
func CheckSortition(proof []byte) bool {
	output, err := VRFOutputFromProof(proof)
	if err != nil {
		return false
	}
	return output[0] < 0xA0
}
