package miner

import (
	"math/big"
	"testing"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/consensus/ethash"
	"github.com/cryptoecc/WorldLand/core"
	"github.com/cryptoecc/WorldLand/core/rawdb"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/params"
)

func TestEnrollmentQueueIdempotentAndBranchBound(t *testing.T) {
	cfg := *params.AllEthashProtocolChanges
	cfg.ChainID = big.NewInt(1337)
	engine := ethash.NewFaker()
	w, backend := newTestWorker(t, &cfg, engine, rawdb.NewMemoryDatabase(), 0)
	defer w.close()
	defer backend.chain.Stop()
	defer backend.txPool.Stop()
	genesis := backend.chain.Genesis()
	makeBranch := func(extra byte) *types.Block {
		blocks, _ := core.GenerateChain(&cfg, genesis, engine, backend.db, 1, func(_ int, b *core.BlockGen) { b.SetExtra([]byte{extra}) })
		return blocks[0]
	}
	a, b := makeBranch(1), makeBranch(2)
	if _, err := backend.chain.InsertChain([]*types.Block{a}); err != nil {
		t.Fatal(err)
	}
	registry := common.HexToAddress("0x801")
	selector := crypto.Keccak256([]byte("publishProducerChallenge(bytes32,bytes,bytes,bytes32,bytes)"))[:4]
	makeTx := func(nonce uint64, value int64) *types.Transaction {
		tx, err := types.SignTx(types.NewTransaction(nonce, registry, big.NewInt(value), 500000, big.NewInt(params.InitialBaseFee), selector), types.MakeSigner(&cfg, big.NewInt(2)), testBankKey)
		if err != nil {
			t.Fatal(err)
		}
		return tx
	}
	parentA := a.Hash()
	tx := makeTx(0, 0)
	for i := 0; i < 2; i++ {
		if err := w.submitPrivateEnrollmentForParent(2, tx, &parentA); err != nil {
			t.Fatalf("retry %d: %v", i, err)
		}
	}
	queued, err := w.enrollmentQueue(2, parentA)
	if err != nil || len(queued) != 1 || queued[0].Hash() != tx.Hash() {
		t.Fatalf("queue = %v, %v", queued, err)
	}
	if err := w.submitPrivateEnrollmentForParent(2, makeTx(0, 1), &parentA); err == nil {
		t.Fatal("accepted conflicting nonce")
	}
	if err := backend.chain.SetHead(0); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.chain.InsertChain([]*types.Block{b}); err != nil {
		t.Fatal(err)
	}
	parentB := b.Hash()
	if _, err := w.enrollmentQueue(2, parentA); err == nil {
		t.Fatal("read orphaned queue")
	}
	if err := w.submitPrivateEnrollmentForParent(2, tx, &parentA); err == nil {
		t.Fatal("staged against orphaned parent")
	}
	queued, err = w.enrollmentQueue(2, parentB)
	if err != nil || len(queued) != 0 {
		t.Fatalf("old branch leaked: %v %v", queued, err)
	}
	if err := w.submitPrivateEnrollmentForParent(2, makeTx(0, 2), &parentB); err != nil {
		t.Fatal(err)
	}
	if len(w.privateEnrollmentForParent(2, parentA)) != 0 {
		t.Fatal("orphaned template received replacement transactions")
	}
}

func TestSealingResultRequiresExactTemplate(t *testing.T) {
	engine := ethash.NewFaker()
	a := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1), Time: 10, Root: common.HexToHash("0x01")})
	bHeader := a.Header()
	bHeader.Root = common.HexToHash("0x02")
	b := types.NewBlockWithHeader(bHeader)
	ta, tb := &task{block: a}, &task{block: b}
	w := &worker{engine: engine, pendingTasks: map[common.Hash]*task{engine.SealHash(a.Header()): ta, engine.SealHash(b.Header()): tb}}
	if w.taskForResult(b) != tb {
		t.Fatal("selected another same-height task")
	}
	changed := b.Header()
	changed.Time++
	if w.taskForResult(b.WithSeal(changed)) != nil {
		t.Fatal("guessed task for changed execution context")
	}
	changed = b.Header()
	changed.ParentHash = common.HexToHash("0x03")
	if w.taskForResult(b.WithSeal(changed)) != nil {
		t.Fatal("guessed task from another parent")
	}
}
