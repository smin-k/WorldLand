//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/crypto/secp256k1"
	"github.com/cryptoecc/WorldLand/log"
	"github.com/cryptoecc/WorldLand/params"
)

// Keep the production cryptographic verification path, including ECCPoW, but
// reduce the test-only nonce search to the existing Seoul difficulty floor.
// These tests must not run in parallel because they temporarily change a
// package consensus constant. No deployed chain configuration is changed.
func batchTestDifficulty(t *testing.T) {
	t.Helper()
	previous := VCTMinimumDifficulty
	VCTMinimumDifficulty = new(big.Int).Set(SeoulDifficulty)
	t.Cleanup(func() { VCTMinimumDifficulty = previous })
}

func makeBatchHeaders(t *testing.T, delay uint64) (*ECC, *mockChainReader, []*types.Header) {
	t.Helper()
	cfg := &params.ChainConfig{
		ChainID: big.NewInt(91510), SeoulBlock: big.NewInt(0),
		AnnapurnaBlock: big.NewInt(0), VCTBlock: big.NewInt(1), TPMGatedBlock: big.NewInt(1),
		Vct: &params.VctConfig{SeedDelay: delay, InitialEligibilityThreshold: big.NewInt(32)},
	}
	ecc := &ECC{config: Config{PowMode: ModeNormal, Log: log.Root()}, chainID: cfg.ChainID}
	secret := make([]byte, 32)
	secret[31] = 1
	public, err := secp256k1.VRFPubkeyFromSeckey(secret)
	if err != nil {
		t.Fatal(err)
	}
	account, err := crypto.ToECDSA(secret)
	if err != nil {
		t.Fatal(err)
	}
	workKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	genesis := &types.Header{
		Number: new(big.Int), Difficulty: new(big.Int).Set(SeoulDifficulty),
		UncleHash: types.EmptyUncleHash, GasLimit: 30_000_000, Time: 1_700_000_000,
	}
	chain := &mockChainReader{cfg: cfg, headers: map[common.Hash]*types.Header{genesis.Hash(): genesis}}
	did := crypto.Keccak256Hash([]byte("batch-verification-device"))
	parent := genesis
	headers := make([]*types.Header, 3)
	for i := range headers {
		header := &types.Header{
			ParentHash: parent.Hash(), UncleHash: types.EmptyUncleHash,
			Number: new(big.Int).SetUint64(uint64(i + 1)), Coinbase: crypto.PubkeyToAddress(account.PublicKey),
			GasLimit: parent.GasLimit, Time: parent.Time + VCTFutureTolerance + TimeoutEnd,
			VRFPublicKey: public, TPMDID: did.Bytes(),
			TPMWorkPublicKey: elliptic.Marshal(elliptic.P256(), workKey.X, workKey.Y),
		}
		header.Difficulty = ecc.CalcDifficulty(chain, header.Time, parent)
		header.EligibilityThreshold = ecc.CalcEligibilityThreshold(chain, header.Time, parent)
		message, err := ecc.delayedVRFMessage(chain, parent, header.Number.Uint64())
		if err != nil {
			t.Fatal(err)
		}
		header.VRFProof, _, err = VRFProve(secret, public, message)
		if err != nil {
			t.Fatal(err)
		}
		mineTPMConsensusGateHeader(t, ecc, header, workKey)
		if err := ecc.VerifyHeader(chain, header, true); err != nil {
			t.Fatalf("sequential header %d: %v", i+1, err)
		}
		chain.headers[header.Hash()] = header
		headers[i], parent = header, header
	}
	// Return a genuinely fresh receiving chain: none of the batch headers has
	// been inserted. Each fixture was independently checked sequentially above.
	chain.headers = map[common.Hash]*types.Header{genesis.Hash(): genesis}
	return ecc, chain, headers
}

func verifyBatchResults(ecc *ECC, chain *mockChainReader, headers []*types.Header, seals []bool) []error {
	abort, results := ecc.VerifyHeaders(chain, headers, seals)
	defer close(abort)
	errors := make([]error, len(headers))
	for i := range errors {
		errors[i] = <-results
	}
	return errors
}

func TestVCTVerifyHeadersFreshBatch(t *testing.T) {
	batchTestDifficulty(t)
	for _, delay := range []uint64{1, 2} {
		t.Run(fmt.Sprintf("seed_delay_%d", delay), func(t *testing.T) {
			ecc, chain, headers := makeBatchHeaders(t, delay)
			// These are independent receiving engines: they have never mined,
			// prepared a template, or been assigned a chain ID by the fixture.
			fresh := &ECC{config: Config{PowMode: ModeNormal, Log: log.Root()}}
			if err := fresh.VerifyHeader(chain, headers[0], true); err != nil {
				t.Fatalf("fresh validator rejected first header: %v", err)
			}
			// Full insertion, sampled header validation, and seal-skipping
			// reimports all need branch-local batch ancestry. The last also
			// exercises the controller's boost after a timed-out parent.
			for _, seals := range [][]bool{{true, true, true}, {false, false, true}, {false, false, false}} {
				for _, shared := range []bool{false, true} {
					peer := &ECC{config: Config{PowMode: ModeNormal, Log: log.Root()}}
					if shared {
						peer.shared = &ECC{config: Config{PowMode: ModeNormal, Log: log.Root()}}
					}
					for i, err := range verifyBatchResults(peer, chain, headers, seals) {
						if err != nil {
							t.Errorf("fresh batch header %d (seals=%v shared=%v) rejected after sequential success: %v", i+1, seals, shared, err)
						}
					}
				}
			}
			if len(chain.headers) != 1 {
				t.Fatal("batch verification inserted headers into the receiving chain")
			}
			// A bad predecessor must still produce the first ordered error;
			// supplying it as provisional batch ancestry cannot authorize its
			// import. The production importer stops at this first error.
			bad := append([]*types.Header(nil), headers...)
			bad[0] = types.CopyHeader(headers[0])
			bad[0].VRFProof[0] ^= 0xff
			results := verifyBatchResults(ecc, chain, bad, []bool{true, true, true})
			if results[0] == nil {
				t.Fatal("invalid predecessor VRF was accepted in batch context")
			}
			if len(chain.headers) != 1 {
				t.Fatal("invalid batch changed receiving chain state")
			}
		})
	}
}

func TestBatchHeaderReaderPrefixAndBranch(t *testing.T) {
	genesis := &types.Header{Number: new(big.Int), Difficulty: big.NewInt(1)}
	left := &types.Header{Number: big.NewInt(1), ParentHash: genesis.Hash(), Difficulty: big.NewInt(1), Extra: []byte("left")}
	right := types.CopyHeader(left)
	right.Extra = []byte("right")
	child := &types.Header{Number: big.NewInt(2), ParentHash: left.Hash(), Difficulty: big.NewInt(1)}
	stored := &mockChainReader{headers: map[common.Hash]*types.Header{genesis.Hash(): genesis, right.Hash(): right}}
	view := &batchHeaderReader{ChainHeaderReader: stored, headers: batchHeaderIndex([]*types.Header{left, child}), limit: 1}
	if got := view.GetHeader(left.Hash(), 1); got != left {
		t.Fatal("batch branch parent was replaced by stored competing branch")
	}
	if got := view.GetHeader(right.Hash(), 1); got != right {
		t.Fatal("stored exact-hash lookup was not preserved")
	}
	if got := view.GetHeader(left.Hash(), 2); got != nil {
		t.Fatal("batch ancestor accepted at wrong height")
	}
	if got := view.GetHeader(child.Hash(), 2); got != nil {
		t.Fatal("current/future batch header was exposed as ancestry")
	}
	if got := view.GetHeaderByHash(child.Hash()); got != nil {
		t.Fatal("current/future batch header was exposed by hash")
	}
	if got := view.GetHeader(genesis.Hash(), 0); got != genesis {
		t.Fatal("stored ancestor lookup failed")
	}
}
