//go:build !enrollmentresearch
// +build !enrollmentresearch

package tpmenroll

import (
	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
	"math/big"
)

func researchResponseChallenge(_ *big.Int, _ common.Address, _ common.Hash, _, _ uint64, _, original common.Hash) common.Hash {
	return original
}
func researchMutateResponse(_ *big.Int, _, _ uint64, _ *tpmwork.KeyCertification) {}
