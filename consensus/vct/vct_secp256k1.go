//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"errors"
	"math"
	"math/big"

	secp256k1pkg "github.com/cryptoecc/WorldLand/crypto/secp256k1"
)

// Progressive timeout parameters (WIP-6).
// These are consensus-critical constants; changing them requires a hard fork.
const (
	// TimeoutStart is the elapsed delta-t (seconds) after which the sortition
	// threshold begins expanding beyond the base threshold.
	TimeoutStart uint64 = 15

	// TimeoutEnd is the effective elapsed delta-t (seconds) at which all outputs
	// are eligible. It is ceil(-10s * ln(0.001)), the 99.9% quantile of an
	// exponential block-finding process with 10 second mean.
	TimeoutEnd uint64 = 70

	// VCTFutureTolerance is subtracted from raw header delta-t before applying
	// progressive timeout sortition, so permitted future timestamps do not grant
	// early eligibility.
	VCTFutureTolerance uint64 = 5
)

var (
	errInvalidVRFProofLen = errors.New("VRF proof must be 81 bytes")

	// SortitionDenominator is 2^256, the size of the VRF output space.
	SortitionDenominator = new(big.Int).Lsh(big.NewInt(1), 256)
	// SortitionBase is the target base threshold after bootstrap: p = 1/8.
	SortitionBase = new(big.Int).Lsh(big.NewInt(1), 253)
	// SortitionThresholdMax accepts every 32-byte VRF output.
	SortitionThresholdMax = new(big.Int).Set(SortitionDenominator)
)

// VRFProve generates an 81-byte secp256k1 VRF proof and the corresponding
// 32-byte output.
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

// VRFOutputFromProof extracts the 32-byte VRF output from a proof without
// verifying it. Only call after a successful VRFProve or VRFVerify.
func VRFOutputFromProof(proof []byte) ([32]byte, error) {
	if len(proof) != 81 {
		return [32]byte{}, errInvalidVRFProofLen
	}
	var proofArr [81]byte
	copy(proofArr[:], proof)
	return secp256k1pkg.VRFProofToHash(proofArr)
}

func cloneThreshold(x *big.Int) *big.Int {
	if x == nil || x.Sign() <= 0 {
		return new(big.Int).Set(SortitionBase)
	}
	if x.Cmp(SortitionThresholdMax) >= 0 {
		return new(big.Int).Set(SortitionThresholdMax)
	}
	if x.Cmp(SortitionBase) < 0 {
		return new(big.Int).Set(SortitionBase)
	}
	return new(big.Int).Set(x)
}

func thresholdProbability(threshold *big.Int) float64 {
	t := cloneThreshold(threshold)
	if t.Cmp(SortitionThresholdMax) >= 0 {
		return 1
	}
	r := new(big.Rat).SetFrac(t, SortitionDenominator)
	p, _ := r.Float64()
	return p
}

func thresholdFromProbability(p float64) *big.Int {
	if p >= 1 {
		return new(big.Int).Set(SortitionThresholdMax)
	}
	if p <= 0 {
		return new(big.Int)
	}
	f := new(big.Float).SetPrec(320).SetMode(big.ToZero).SetFloat64(p)
	f.Mul(f, new(big.Float).SetPrec(320).SetInt(SortitionDenominator))
	out, _ := f.Int(nil)
	return out
}

// ConfigSortitionThreshold converts a config value into the consensus threshold.
// Values 1..256 are treated as legacy byte-scale probabilities for convenience:
// 32 => 12.5%, 128 => 50%, 256 => all eligible. Larger values are interpreted
// as full uint256 thresholds.
func ConfigSortitionThreshold(value *big.Int) *big.Int {
	if value == nil || value.Sign() <= 0 {
		return new(big.Int).Set(SortitionThresholdMax)
	}
	if value.Cmp(big.NewInt(256)) <= 0 {
		if value.Cmp(big.NewInt(256)) == 0 {
			return new(big.Int).Set(SortitionThresholdMax)
		}
		out := new(big.Int).Lsh(new(big.Int).Set(value), 248)
		return cloneThreshold(out)
	}
	return cloneThreshold(value)
}

// SortitionThresholdAt returns the uint256 eligibility threshold for a given
// elapsed block time deltaT.
func SortitionThresholdAt(baseThreshold *big.Int, deltaT uint64) *big.Int {
	base := cloneThreshold(baseThreshold)
	if base.Cmp(SortitionThresholdMax) >= 0 {
		return new(big.Int).Set(SortitionThresholdMax)
	}
	if deltaT < TimeoutStart {
		return base
	}
	if deltaT >= TimeoutEnd {
		return new(big.Int).Set(SortitionThresholdMax)
	}
	p0 := thresholdProbability(base)
	ts := float64(TimeoutStart)
	te := float64(TimeoutEnd)
	tau := (te - ts) / math.Log(1.0/p0)
	p := p0 * math.Exp(float64(deltaT-TimeoutStart)/tau)
	threshold := thresholdFromProbability(p)
	if threshold.Cmp(base) < 0 {
		return base
	}
	return threshold
}

// EffectiveDeltaT returns the elapsed time used by progressive timeout
// sortition after discounting the consensus future-timestamp allowance.
func EffectiveDeltaT(rawDeltaT uint64) uint64 {
	if rawDeltaT <= VCTFutureTolerance {
		return 0
	}
	return rawDeltaT - VCTFutureTolerance
}

// CheckSortition returns true if the VRF proof passes the fixed base sortition
// threshold. The 32-byte VRF output is interpreted as a big-endian uint256.
func CheckSortition(proof []byte) bool {
	output, err := VRFOutputFromProof(proof)
	if err != nil {
		return false
	}
	return SortitionEligibleWithBase(output, SortitionBase, 0)
}

func SortitionEligible(output [32]byte, deltaT uint64) bool {
	return SortitionEligibleWithBase(output, SortitionBase, deltaT)
}

// SortitionEligibleWithBase returns true if the VRF output passes the
// time-dependent threshold derived from the block's base threshold.
func SortitionEligibleWithBase(output [32]byte, baseThreshold *big.Int, deltaT uint64) bool {
	if deltaT >= TimeoutEnd {
		return true
	}
	threshold := SortitionThresholdAt(baseThreshold, deltaT)
	if threshold.Cmp(SortitionThresholdMax) >= 0 {
		return true
	}
	return new(big.Int).SetBytes(output[:]).Cmp(threshold) < 0
}

func CheckSortitionWithTime(proof []byte, deltaT uint64) bool {
	return CheckSortitionWithBaseAndTime(proof, SortitionBase, deltaT)
}

// CheckSortitionWithBaseAndTime is CheckSortitionWithTime parameterized by the
// block's adaptive base threshold.
func CheckSortitionWithBaseAndTime(proof []byte, baseThreshold *big.Int, deltaT uint64) bool {
	output, err := VRFOutputFromProof(proof)
	if err != nil {
		return false
	}
	return SortitionEligibleWithBase(output, baseThreshold, deltaT)
}

func SortitionSubmitDelay(output [32]byte) uint64 {
	return SortitionSubmitDelayWithBase(output, SortitionBase)
}

// SortitionSubmitDelayWithBase returns the minimum elapsed seconds needed
// under the provided adaptive base threshold.
func SortitionSubmitDelayWithBase(output [32]byte, baseThreshold *big.Int) uint64 {
	base := cloneThreshold(baseThreshold)
	if base.Cmp(SortitionThresholdMax) >= 0 || new(big.Int).SetBytes(output[:]).Cmp(base) < 0 {
		return 0
	}
	next := new(big.Int).SetBytes(output[:])
	next.Add(next, big.NewInt(1))
	qRat := new(big.Rat).SetFrac(next, SortitionDenominator)
	q, _ := qRat.Float64()
	p0 := thresholdProbability(base)
	ts := float64(TimeoutStart)
	te := float64(TimeoutEnd)
	tau := (te - ts) / math.Log(1.0/p0)
	delay := ts + tau*math.Log(q/p0)
	if delay >= te {
		return TimeoutEnd
	}
	out := uint64(math.Ceil(delay))
	if out < TimeoutStart {
		out = TimeoutStart
	}
	for out < TimeoutEnd && !SortitionEligibleWithBase(output, base, out) {
		out++
	}
	return out
}
