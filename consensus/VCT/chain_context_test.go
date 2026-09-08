//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"math/big"
	"sync"
	"testing"

	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/params"
)

func TestVCTChainContextCopiesAndRejectsReuse(t *testing.T) {
	chain := &mockChainReader{cfg: &params.ChainConfig{ChainID: big.NewInt(91510)}}
	ecc := &ECC{}
	if err := ecc.bindChainContext(chain); err != nil {
		t.Fatal(err)
	}
	if ecc.chainID == chain.cfg.ChainID {
		t.Fatal("engine retains the mutable chain-config ID pointer")
	}
	chain.cfg.ChainID.SetInt64(91511)
	if got := new(big.Int).SetBytes(ecc.chainIDBytes()); got.Int64() != 91510 {
		t.Fatalf("config mutation changed bound crypto domain to %v", got)
	}
	// Rejection must precede even known-header lookup or cryptographic work.
	if err := ecc.VerifyHeader(chain, &types.Header{}, true); err == nil {
		t.Fatal("validator silently reused an engine across chains")
	}
	results := verifyBatchResults(ecc, chain, []*types.Header{{}}, []bool{true})
	if results[0] == nil {
		t.Fatal("batch validator silently reused an engine across chains")
	}
	if err := ecc.Prepare(chain, &types.Header{}); err == nil {
		t.Fatal("miner preparation silently rebound an engine")
	}
}

func TestVCTSharedChainContextRejectsReuse(t *testing.T) {
	shared := &ECC{}
	first, second := &ECC{shared: shared}, &ECC{shared: shared}
	chain := &mockChainReader{cfg: &params.ChainConfig{ChainID: big.NewInt(91510)}}
	if err := first.bindChainContext(chain); err != nil {
		t.Fatal(err)
	}
	if first.chainID == shared.chainID || first.chainID == chain.cfg.ChainID || shared.chainID == chain.cfg.ChainID {
		t.Fatal("wrapper, shared engine and config must own separate ID copies")
	}
	other := &mockChainReader{cfg: &params.ChainConfig{ChainID: big.NewInt(91511)}}
	if err := second.bindChainContext(other); err == nil {
		t.Fatal("second wrapper silently changed the shared engine domain")
	}
	if err := second.bindChainContext(chain); err != nil {
		t.Fatalf("second wrapper could not use the original shared chain: %v", err)
	}
}

func TestVCTChainContextConcurrentBinding(t *testing.T) {
	ecc := &ECC{}
	accepted := make(chan int64, 32)
	var workers sync.WaitGroup
	for i := 0; i < cap(accepted); i++ {
		workers.Add(1)
		go func(id int64) {
			defer workers.Done()
			chain := &mockChainReader{cfg: &params.ChainConfig{ChainID: big.NewInt(id)}}
			if err := ecc.bindChainContext(chain); err == nil {
				accepted <- id
			}
		}(91510 + int64(i%2))
	}
	workers.Wait()
	close(accepted)
	bound := new(big.Int).SetBytes(ecc.chainIDBytes()).Int64()
	count := 0
	for id := range accepted {
		count++
		if id != bound {
			t.Fatalf("engine accepted both chain domains: bound %d, also accepted %d", bound, id)
		}
	}
	if count == 0 {
		t.Fatal("engine did not bind either chain")
	}
}
