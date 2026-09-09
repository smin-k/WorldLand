//go:build enrollmentresearch
// +build enrollmentresearch

package tpmproducer

import (
	"github.com/cryptoecc/WorldLand/common"
	"math/big"
	"os"
)

// Research build only: suppress exactly the first-slot approval for the named
// identity on the isolated campaign chain. Never changes validation or quorum.
func researchWithholdApproval(chainID *big.Int, identity common.Hash, slot, first uint64) bool {
	if chainID == nil || chainID.Cmp(big.NewInt(103994)) != 0 || slot != first {
		return false
	}
	target := os.Getenv("WORLDLAND_RESEARCH_WITHHOLD_DID")
	if len(target) != 66 || identity == (common.Hash{}) || common.HexToHash(target) != identity {
		return false
	}
	path := os.Getenv("WORLDLAND_RESEARCH_WITHHOLD_MARKER")
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
