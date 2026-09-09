//go:build !enrollmentresearch
// +build !enrollmentresearch

package tpmproducer

import (
	"github.com/cryptoecc/WorldLand/common"
	"math/big"
)

func researchWithholdApproval(_ *big.Int, _ common.Hash, _, _ uint64) bool { return false }
