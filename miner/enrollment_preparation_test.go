package miner

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/consensus/ethash"
	"github.com/cryptoecc/WorldLand/core"
	"github.com/cryptoecc/WorldLand/core/rawdb"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/params"
)

type prepareFunc func(context.Context, *types.Header) error

func (f prepareFunc) Prepare(ctx context.Context, h *types.Header) error { return f(ctx, h) }

// Exercises the real worker task path: no task, including the early empty task,
// may reach the sealer until preparation finishes, even with an instant fake seal.
func TestIntegratedEnrollmentPrecedesEverySealingTask(t *testing.T) {
	cfg := *params.AllEthashProtocolChanges
	w, b := newTestWorker(t, &cfg, ethash.NewFaker(), rawdb.NewMemoryDatabase(), 0)
	defer b.chain.Stop()
	defer b.txPool.Stop()
	defer w.close()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var prepared common.Hash
	tasks := make(chan *task, 10)
	w.skipSealHook = func(task *task) bool {
		select {
		case tasks <- task:
		default:
		}
		return true
	}
	p := prepareFunc(func(ctx context.Context, parent *types.Header) error {
		once.Do(func() { close(entered) })
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		if len(w.privateEnrollmentForParent(parent.Number.Uint64()+1, parent.Hash())) > 0 {
			return nil
		}
		state, err := b.chain.StateAt(parent.Root)
		if err != nil {
			return err
		}
		selector := crypto.Keccak256([]byte("publishProducerChallenge(bytes32,bytes,bytes,bytes32,bytes)"))[:4]
		tx, err := types.SignTx(types.NewTransaction(state.GetNonce(testBankAddress), common.HexToAddress("0x801"), new(big.Int), 500000, big.NewInt(params.InitialBaseFee), selector), types.MakeSigner(&cfg, new(big.Int).Add(parent.Number, big.NewInt(1))), testBankKey)
		if err != nil {
			return err
		}
		prepared = tx.Hash()
		hash := parent.Hash()
		return w.submitPrivateEnrollmentForParent(parent.Number.Uint64()+1, tx, &hash)
	})
	m := &Miner{worker: w}
	if err := m.SetEnrollmentPreparer(p, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	w.start()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("preparation never entered")
	}
	select {
	case <-tasks:
		t.Fatal("sealer received a task before preparation")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case task := <-tasks:
		found := false
		for _, tx := range task.block.Transactions() {
			if tx.Hash() == prepared {
				found = true
			}
		}
		if !found {
			t.Fatal("prepared challenge absent from first sealing task")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("prepared candidate never reached sealer")
	}
}

func TestEnrollmentPreparationCancellation(t *testing.T) {
	for _, mode := range []string{"timeout", "head-change", "shutdown", "error"} {
		t.Run(mode, func(t *testing.T) {
			cfg := *params.AllEthashProtocolChanges
			engine := ethash.NewFaker()
			w, b := newTestWorker(t, &cfg, engine, rawdb.NewMemoryDatabase(), 0)
			defer b.chain.Stop()
			defer b.txPool.Stop()
			closed := false
			defer func() {
				if !closed {
					w.close()
				}
			}()
			entered := make(chan struct{})
			p := prepareFunc(func(ctx context.Context, _ *types.Header) error {
				close(entered)
				if mode == "error" {
					return errors.New("preparation failed")
				}
				<-ctx.Done()
				return ctx.Err()
			})
			timeout := 2 * time.Second
			if mode == "timeout" {
				timeout = 20 * time.Millisecond
			}
			m := &Miner{worker: w}
			if err := m.SetEnrollmentPreparer(p, timeout); err != nil {
				t.Fatal(err)
			}
			parent := b.chain.CurrentBlock().Header()
			done := make(chan error, 1)
			go func() { done <- w.prepareEnrollment(parent) }()
			<-entered
			if mode == "head-change" {
				blocks, _ := core.GenerateChain(&cfg, b.chain.CurrentBlock(), engine, b.db, 1, nil)
				if _, err := b.chain.InsertChain(blocks); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "shutdown" {
				w.close()
				closed = true
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("failed/cancelled preparation accepted")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("preparation did not cancel")
			}
			if w.enrollmentCanSeal(parent.Hash()) {
				t.Fatal("cancelled parent marked ready")
			}
		})
	}
}
