//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"errors"
	"math"

	secp256k1pkg "github.com/cryptoecc/WorldLand/crypto/secp256k1"
)

// Progressive timeout parameters (WIP-6).
// These are consensus-critical constants — changing them requires a hard fork.
const (
	// SortitionBase is the VRF first-byte threshold for immediate (base) eligibility:
	// output[0] < SortitionBase → immediately eligible.
	// Gives p_h^0 = 160/256 ≈ 62.5%.
	SortitionBase uint8 = 0xA0

	// TimeoutStart is the Δt (seconds since parent block) after which the sortition
	// threshold begins expanding beyond p_h^0.  Below this, p_h(Δt) = p_h^0.
	TimeoutStart uint64 = 15

	// TimeoutEnd is the Δt (seconds) at which p_h(Δt) = 1 (all miners eligible).
	// A block with Δt ≥ TimeoutEnd is always accepted regardless of VRF output.
	TimeoutEnd uint64 = 60
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

// CheckSortition returns true if the VRF proof passes the fixed base sortition threshold.
// Used for pre-WIP-6 blocks and as the immediate-eligibility check during mining.
// Threshold: output[0] < SortitionBase (≈ 62.5%).
func CheckSortition(proof []byte) bool {
	output, err := VRFOutputFromProof(proof)
	if err != nil {
		return false
	}
	return output[0] < SortitionBase
}

// sortitionThresholdByte returns the VRF first-byte eligibility threshold for a
// given elapsed block time deltaT = blockTimestamp - parentTimestamp (seconds).
// Returns 255 when deltaT ≥ TimeoutEnd (handled separately as always-eligible).
func sortitionThresholdByte(deltaT uint64) uint8 {
	if deltaT < TimeoutStart {
		return SortitionBase
	}
	if deltaT >= TimeoutEnd {
		return 255 // caller should use SortitionEligible which short-circuits for >= TimeoutEnd
	}
	// τ_h = (t_e - t_s) / ln(1 / p_h^0)
	p0 := float64(SortitionBase) / 256.0
	ts := float64(TimeoutStart)
	te := float64(TimeoutEnd)
	tau := (te - ts) / math.Log(1.0/p0)
	p := p0 * math.Exp(float64(deltaT-TimeoutStart)/tau)
	if p >= 1.0 {
		return 255
	}
	threshold := uint8(p * 256.0)
	if threshold < SortitionBase {
		return SortitionBase
	}
	return threshold
}

// SortitionEligible returns true if the VRF output passes the time-dependent
// sortition threshold p_h(deltaT).  Always true when deltaT ≥ TimeoutEnd.
func SortitionEligible(output [32]byte, deltaT uint64) bool {
	if deltaT >= TimeoutEnd {
		return true
	}
	threshold := sortitionThresholdByte(deltaT)
	if threshold == 255 {
		return true
	}
	return output[0] < threshold
}

// CheckSortitionWithTime returns true if the VRF proof passes the progressive
// timeout sortition threshold for the given elapsed block time deltaT (seconds).
func CheckSortitionWithTime(proof []byte, deltaT uint64) bool {
	output, err := VRFOutputFromProof(proof)
	if err != nil {
		return false
	}
	return SortitionEligible(output, deltaT)
}

// SortitionSubmitDelay returns the minimum seconds after the parent block
// timestamp at which a miner with the given VRF output first byte may submit a
// block.  Returns 0 if the miner is immediately eligible (firstByte < SortitionBase).
//
// The delay is chosen so that at Δt = delay, p_h(Δt) strictly exceeds firstByte/256,
// i.e. the verifier's CheckSortitionWithTime call will pass.
func SortitionSubmitDelay(firstByte uint8) uint64 {
	if firstByte < SortitionBase {
		return 0
	}
	// Use (firstByte+1)/256 so that threshold > firstByte/256 at submission time.
	q := float64(int(firstByte)+1) / 256.0 // safe: int(255)+1 = 256
	p0 := float64(SortitionBase) / 256.0
	ts := float64(TimeoutStart)
	te := float64(TimeoutEnd)
	tau := (te - ts) / math.Log(1.0/p0)
	delay := ts + tau*math.Log(q/p0)
	if delay >= te {
		return TimeoutEnd
	}
	return uint64(math.Ceil(delay))
}
