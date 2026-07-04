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
	// TimeoutStart is the elapsed delta-t (seconds) after which the eligibility
	// threshold begins expanding beyond the base threshold.
	TimeoutStart uint64 = 15

	// TimeoutEnd is the effective elapsed delta-t (seconds) at which all outputs
	// are eligible. It is ceil(-10s * ln(0.001)), the 99.9% quantile of an
	// exponential block-finding process with 10 second mean.
	TimeoutEnd uint64 = 70

	// VCTFutureTolerance is subtracted from raw header delta-t before applying
	// progressive timeout eligibility, so permitted future timestamps do not grant
	// early eligibility.
	VCTFutureTolerance uint64 = 5
)

var (
	errInvalidVRFProofLen = errors.New("VRF proof must be 81 bytes")

	// EligibilityDenominator is 2^256, the size of the VRF output space.
	EligibilityDenominator = new(big.Int).Lsh(big.NewInt(1), 256)
	// EligibilityBase is the target base threshold after bootstrap: p = 1/8.
	EligibilityBase = new(big.Int).Lsh(big.NewInt(1), 253)
	// EligibilityThresholdMax accepts every 32-byte VRF output.
	EligibilityThresholdMax = new(big.Int).Set(EligibilityDenominator)
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
		return new(big.Int).Set(EligibilityBase)
	}
	if x.Cmp(EligibilityThresholdMax) >= 0 {
		return new(big.Int).Set(EligibilityThresholdMax)
	}
	if x.Cmp(EligibilityBase) < 0 {
		return new(big.Int).Set(EligibilityBase)
	}
	return new(big.Int).Set(x)
}

func thresholdProbability(threshold *big.Int) float64 {
	t := cloneThreshold(threshold)
	if t.Cmp(EligibilityThresholdMax) >= 0 {
		return 1
	}
	r := new(big.Rat).SetFrac(t, EligibilityDenominator)
	p, _ := r.Float64()
	return p
}

func thresholdFromProbability(p float64) *big.Int {
	if p >= 1 {
		return new(big.Int).Set(EligibilityThresholdMax)
	}
	if p <= 0 {
		return new(big.Int)
	}
	f := new(big.Float).SetPrec(320).SetMode(big.ToZero).SetFloat64(p)
	f.Mul(f, new(big.Float).SetPrec(320).SetInt(EligibilityDenominator))
	out, _ := f.Int(nil)
	return out
}

// ConfigEligibilityThreshold converts a config value into the consensus threshold.
// Values 1..256 are treated as legacy byte-scale probabilities for convenience:
// 32 => 12.5%, 128 => 50%, 256 => all eligible. Larger values are interpreted
// as full uint256 thresholds.
func ConfigEligibilityThreshold(value *big.Int) *big.Int {
	if value == nil || value.Sign() <= 0 {
		return new(big.Int).Set(EligibilityThresholdMax)
	}
	if value.Cmp(big.NewInt(256)) <= 0 {
		if value.Cmp(big.NewInt(256)) == 0 {
			return new(big.Int).Set(EligibilityThresholdMax)
		}
		out := new(big.Int).Lsh(new(big.Int).Set(value), 248)
		return cloneThreshold(out)
	}
	return cloneThreshold(value)
}

// EligibilityThresholdAt returns the uint256 eligibility threshold for a given
// elapsed block time deltaT.
func EligibilityThresholdAt(baseThreshold *big.Int, deltaT uint64) *big.Int {
	base := cloneThreshold(baseThreshold)
	if base.Cmp(EligibilityThresholdMax) >= 0 {
		return new(big.Int).Set(EligibilityThresholdMax)
	}
	if deltaT < TimeoutStart {
		return base
	}
	if deltaT >= TimeoutEnd {
		return new(big.Int).Set(EligibilityThresholdMax)
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
// eligibility after discounting the consensus future-timestamp allowance.
func EffectiveDeltaT(rawDeltaT uint64) uint64 {
	if rawDeltaT <= VCTFutureTolerance {
		return 0
	}
	return rawDeltaT - VCTFutureTolerance
}

// CheckEligibility returns true if the VRF proof passes the fixed base eligibility
// threshold. The 32-byte VRF output is interpreted as a big-endian uint256.
func CheckEligibility(proof []byte) bool {
	output, err := VRFOutputFromProof(proof)
	if err != nil {
		return false
	}
	return EligibilityPassesWithBase(output, EligibilityBase, 0)
}

func EligibilityPasses(output [32]byte, deltaT uint64) bool {
	return EligibilityPassesWithBase(output, EligibilityBase, deltaT)
}

// EligibilityPassesWithBase returns true if the VRF output passes the
// time-dependent threshold derived from the block's base threshold.
func EligibilityPassesWithBase(output [32]byte, baseThreshold *big.Int, deltaT uint64) bool {
	if deltaT >= TimeoutEnd {
		return true
	}
	threshold := EligibilityThresholdAt(baseThreshold, deltaT)
	if threshold.Cmp(EligibilityThresholdMax) >= 0 {
		return true
	}
	return new(big.Int).SetBytes(output[:]).Cmp(threshold) < 0
}

func CheckEligibilityWithTime(proof []byte, deltaT uint64) bool {
	return CheckEligibilityWithBaseAndTime(proof, EligibilityBase, deltaT)
}

// CheckEligibilityWithBaseAndTime is CheckEligibilityWithTime parameterized by the
// block's adaptive base threshold.
func CheckEligibilityWithBaseAndTime(proof []byte, baseThreshold *big.Int, deltaT uint64) bool {
	output, err := VRFOutputFromProof(proof)
	if err != nil {
		return false
	}
	return EligibilityPassesWithBase(output, baseThreshold, deltaT)
}

func EligibilitySubmitDelay(output [32]byte) uint64 {
	return EligibilitySubmitDelayWithBase(output, EligibilityBase)
}

// EligibilitySubmitDelayWithBase returns the minimum elapsed seconds needed
// under the provided adaptive base threshold.
func EligibilitySubmitDelayWithBase(output [32]byte, baseThreshold *big.Int) uint64 {
	base := cloneThreshold(baseThreshold)
	if base.Cmp(EligibilityThresholdMax) >= 0 || new(big.Int).SetBytes(output[:]).Cmp(base) < 0 {
		return 0
	}
	next := new(big.Int).SetBytes(output[:])
	next.Add(next, big.NewInt(1))
	qRat := new(big.Rat).SetFrac(next, EligibilityDenominator)
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
	for out < TimeoutEnd && !EligibilityPassesWithBase(output, base, out) {
		out++
	}
	return out
}
