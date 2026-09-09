//go:build enrollmentresearch
// +build enrollmentresearch

package tpmproducer

import (
	"github.com/cryptoecc/WorldLand/common"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestResearchWithholdingScope(t *testing.T) {
	did := common.HexToHash("0x1234")
	marker := filepath.Join(t.TempDir(), "enabled")
	if err := os.WriteFile(marker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WORLDLAND_RESEARCH_WITHHOLD_DID", did.Hex())
	t.Setenv("WORLDLAND_RESEARCH_WITHHOLD_MARKER", marker)
	if !researchWithholdApproval(big.NewInt(103994), did, 10, 10) {
		t.Fatal("not withheld")
	}
	if researchWithholdApproval(big.NewInt(1), did, 10, 10) || researchWithholdApproval(big.NewInt(103994), did, 11, 10) || researchWithholdApproval(big.NewInt(103994), common.HexToHash("0x5678"), 10, 10) {
		t.Fatal("scope escaped")
	}
	t.Setenv("WORLDLAND_RESEARCH_WITHHOLD_MARKER", "")
	if researchWithholdApproval(big.NewInt(103994), did, 10, 10) {
		t.Fatal("fault remains enabled")
	}
}
