// securityexperiment reproduces the VRF-distribution and ideal-ledger
// experiments reported in the TGPoW paper. All pseudo-random simulations use
// a fixed seed; the VRF samples are produced by the implementation itself.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"

	vct "github.com/cryptoecc/WorldLand/consensus/VCT"
	"github.com/cryptoecc/WorldLand/crypto/secp256k1"
)

const (
	vrfSamples   = 10000
	raceTrials   = 200000
	parentTrials = 200000
)

func main() {
	vrfDistribution()
	idealLedgerRace()
	parentAllocation()
}

func vrfDistribution() {
	seckey := make([]byte, 32)
	seckey[31] = 1
	pubkey, err := secp256k1.VRFPubkeyFromSeckey(seckey)
	must(err)

	bins := make([]int, 16)
	var firstProof []byte
	for i := 0; i < vrfSamples; i++ {
		msg := make([]byte, 79)
		copy(msg, []byte("VCT_VRF"))
		binary.BigEndian.PutUint64(msg[71:], uint64(i+1))
		proof, output, err := vct.VRFProve(seckey, pubkey, msg)
		must(err)
		bins[int(output[0]>>4)]++
		if i == 0 {
			firstProof = append([]byte(nil), proof...)
		}
	}
	repeatMsg := make([]byte, 79)
	copy(repeatMsg, []byte("VCT_VRF"))
	binary.BigEndian.PutUint64(repeatMsg[71:], 1)
	repeatProof, _, err := vct.VRFProve(seckey, pubkey, repeatMsg)
	must(err)
	expected := float64(vrfSamples) / float64(len(bins))
	chiSquare := 0.0
	for _, count := range bins {
		delta := float64(count) - expected
		chiSquare += delta * delta / expected
	}
	fmt.Printf("VRF samples=%d bins=%v chiSquare15df=%.4f deterministic=%t\n",
		vrfSamples, bins, chiSquare, bytes.Equal(firstProof, repeatProof))
}

func idealLedgerRace() {
	rng := rand.New(rand.NewSource(20260828))
	for _, alpha := range []float64{0.30, 0.40} {
		for _, depth := range []int{2, 4, 6, 8} {
			wins := 0
			for trial := 0; trial < raceTrials; trial++ {
				deficit := depth
				for deficit > 0 && deficit < 64 {
					if rng.Float64() < alpha {
						deficit--
					} else {
						deficit++
					}
				}
				if deficit == 0 {
					wins++
				}
			}
			simulated := float64(wins) / raceTrials
			exact := math.Pow(alpha/(1-alpha), float64(depth))
			fmt.Printf("RACE alpha=%.2f depth=%d trials=%d wins=%d simulated=%.6f exact=%.6f\n",
				alpha, depth, raceTrials, wins, simulated, exact)
		}
	}
}

func parentAllocation() {
	const authorizations = 100
	const successProbability = 0.01
	rng := rand.New(rand.NewSource(20260829))
	for _, parents := range []int{1, 2, 4, 8} {
		successes := 0
		for trial := 0; trial < parentTrials; trial++ {
			success := false
			for authorization := 0; authorization < authorizations; authorization++ {
				if rng.Float64() < successProbability {
					success = true
				}
			}
			if success {
				successes++
			}
		}
		exact := 1 - math.Pow(1-successProbability, authorizations)
		fmt.Printf("PARENTS parents=%d authorizations=%d maxPerParent=%d simulated=%.6f exact=%.6f\n",
			parents, authorizations, (authorizations+parents-1)/parents,
			float64(successes)/parentTrials, exact)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
