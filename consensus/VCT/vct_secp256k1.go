//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"errors"
	"math/big"

	secp256k1pkg "github.com/cryptoecc/WorldLand/crypto/secp256k1"
)

// Progressive timeout parameters (WIP-6).
// These are consensus-critical constants; changing them requires a hard fork.
const (
	// TimeoutStart is the elapsed delta-t (seconds) after which the eligibility
	// threshold begins expanding beyond the base threshold.
	TimeoutStart uint64 = 70

	// TimeoutEnd is the effective elapsed delta-t (seconds) at which all outputs
	// are eligible. The 30-second expansion window is evaluated separately from
	// the fixed 70-second start quantile.
	TimeoutEnd uint64 = 100

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

// integerNthRoot returns floor(value^(1/n)). It deliberately uses only
// integer arithmetic: eligibility is consensus critical and must not depend on
// a platform's floating-point exp/log implementation.
func integerNthRoot(value *big.Int, n uint64) *big.Int {
	if value.Sign() <= 0 || n == 0 {
		return new(big.Int)
	}
	if n == 1 {
		return new(big.Int).Set(value)
	}

	// 2^ceil(bitlen/n) is an upper bound on the positive root. Starting above
	// the root makes the integer Newton iteration monotonically decrease.
	x := new(big.Int).Lsh(big.NewInt(1), uint((uint64(value.BitLen())+n-1)/n))
	nBig := new(big.Int).SetUint64(n)
	nMinusOne := new(big.Int).SetUint64(n - 1)
	for {
		xPow := new(big.Int).Exp(x, nMinusOne, nil)
		quotient := new(big.Int).Quo(value, xPow)
		next := new(big.Int).Mul(x, nMinusOne)
		next.Add(next, quotient)
		next.Quo(next, nBig)
		if next.Cmp(x) >= 0 {
			break
		}
		x = next
	}

	// Integer Newton can stop one integer above the floor near an exact
	// boundary. Correct it explicitly so all implementations return the same
	// threshold.
	for new(big.Int).Exp(x, nBig, nil).Cmp(value) > 0 {
		x.Sub(x, big.NewInt(1))
	}
	for {
		next := new(big.Int).Add(x, big.NewInt(1))
		if new(big.Int).Exp(next, nBig, nil).Cmp(value) > 0 {
			break
		}
		x = next
	}
	return x
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
	// At integer second d, preserve the exponential schedule exactly in its
	// algebraic integer form:
	//
	//   threshold(d)^W = base^(TimeoutEnd-d) * 2^256^(d-TimeoutStart),
	//   W = TimeoutEnd-TimeoutStart.
	//
	// The floor W-th root is deterministic. No float conversion, logarithm, or
	// exponential is evaluated by a consensus participant.
	window := TimeoutEnd - TimeoutStart
	elapsed := deltaT - TimeoutStart
	remaining := TimeoutEnd - deltaT
	basePower := new(big.Int).Exp(base, new(big.Int).SetUint64(remaining), nil)
	denominatorPower := new(big.Int).Exp(EligibilityDenominator, new(big.Int).SetUint64(elapsed), nil)
	radical := new(big.Int).Mul(basePower, denominatorPower)
	threshold := integerNthRoot(radical, window)
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
	// Header timestamps and timeout parameters are integer seconds. Searching
	// the bounded window is both exact and cheap (30 steps with current values),
	// and keeps the local scheduling path identical to consensus verification.
	for out := TimeoutStart; out < TimeoutEnd; out++ {
		if EligibilityPassesWithBase(output, base, out) {
			return out
		}
	}
	return TimeoutEnd
}
