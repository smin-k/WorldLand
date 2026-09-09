//go:build enrollmentresearch
// +build enrollmentresearch

package tpmenroll

import (
	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestResponseFaultBounds(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "enabled")
	if err := os.WriteFile(marker, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WORLDLAND_RESEARCH_RESPONSE_MARKER", marker)
	t.Setenv("WORLDLAND_RESEARCH_RESPONSE", "wrong-request")
	original := common.HexToHash("0x1234")
	for _, chain := range []*big.Int{nil, big.NewInt(1)} {
		if got := researchResponseChallenge(chain, common.Address{}, common.Hash{}, 1, 1, common.Hash{}, original); got != original {
			t.Fatal("other chain mutated")
		}
	}
	if got := researchResponseChallenge(big.NewInt(103994), common.Address{}, common.Hash{}, 2, 1, common.Hash{}, original); got != original {
		t.Fatal("non-first slot mutated")
	}
	if got := researchResponseChallenge(big.NewInt(103994), common.Address{}, common.Hash{}, 1, 1, common.Hash{}, original); got == original {
		t.Fatal("fault not applied")
	}
	t.Setenv("WORLDLAND_RESEARCH_RESPONSE", "bad-signature")
	bytes := []byte{1, 2, 3}
	cert := tpmwork.KeyCertification{AttestationSignature: bytes}
	researchMutateResponse(big.NewInt(103994), 1, 1, &cert)
	if cert.AttestationSignature[2] != 2 || bytes[2] != 3 {
		t.Fatal("bad mutation or aliasing")
	}
}
