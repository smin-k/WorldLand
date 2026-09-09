//go:build enrollmentresearch
// +build enrollmentresearch

package tpmenroll

import (
	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
	"log"
	"math/big"
	"os"
)

// Outbound adversarial data only; producer validation and contract are unchanged.
// Requires the research build, isolated chain, first slot, and explicit marker.
func responseFault(chain *big.Int, slot, first uint64) string {
	if chain == nil || chain.Cmp(big.NewInt(103994)) != 0 || slot != first {
		return ""
	}
	marker := os.Getenv("WORLDLAND_RESEARCH_RESPONSE_MARKER")
	if marker == "" {
		return ""
	}
	info, err := os.Stat(marker)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	return os.Getenv("WORLDLAND_RESEARCH_RESPONSE")
}
func researchResponseChallenge(chain *big.Int, registry common.Address, request common.Hash, slot, first uint64, commitment, original common.Hash) common.Hash {
	switch responseFault(chain, slot, first) {
	case "wrong-request":
		other := request
		other[0] ^= 1
		log.Printf("RESEARCH response wrong-request original=%s alternate=%s slot=%d", request, other, slot)
		return tpmregistry.ProducerCertifyChallenge(chain, registry, other, slot, commitment)
	case "wrong-chain":
		log.Printf("RESEARCH response wrong-chain request=%s slot=%d", request, slot)
		return tpmregistry.ProducerCertifyChallenge(new(big.Int).Add(chain, big.NewInt(1)), registry, request, slot, commitment)
	}
	return original
}
func researchMutateResponse(chain *big.Int, slot, first uint64, certification *tpmwork.KeyCertification) {
	if responseFault(chain, slot, first) != "bad-signature" || len(certification.AttestationSignature) == 0 {
		return
	}
	certification.AttestationSignature = append([]byte(nil), certification.AttestationSignature...)
	certification.AttestationSignature[len(certification.AttestationSignature)-1] ^= 1
	log.Printf("RESEARCH response corrupted-certify-signature slot=%d", slot)
}
