package miner

import (
	"context"
	"errors"
	"time"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/core"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/log"
)

// EnrollmentPreparer prepares bounded private transactions for this exact parent.
// Implementations must honor cancellation and must not start a polling loop.
type EnrollmentPreparer interface {
	Prepare(context.Context, *types.Header) error
}

// SetEnrollmentPreparer must be called before starting mining. A preparation error
// discards the candidate, never silently seals it without required preparation.
func (m *Miner) SetEnrollmentPreparer(p EnrollmentPreparer, timeout time.Duration) error {
	if p == nil || timeout <= 0 || timeout > 30*time.Second {
		return errors.New("miner: invalid enrollment preparation configuration")
	}
	if m.Mining() {
		return errors.New("miner: install enrollment preparer before mining")
	}
	m.worker.enrollmentMu.Lock()
	defer m.worker.enrollmentMu.Unlock()
	m.worker.enrollmentPreparer = p
	m.worker.enrollmentTimeout = timeout
	m.worker.enrollmentReady = common.Hash{}
	return nil
}

func (w *worker) prepareEnrollment(parent *types.Header) error {
	w.enrollmentMu.Lock()
	p, timeout := w.enrollmentPreparer, w.enrollmentTimeout
	w.enrollmentReady = common.Hash{}
	w.enrollmentMu.Unlock()
	if p == nil {
		return nil
	}
	if parent == nil {
		return errors.New("miner: missing enrollment parent")
	}
	started := time.Now()
	defer func() {
		log.Info("TPM preparation measurement", "parent", parent.Number, "elapsed", time.Since(started))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	changes := make(chan core.ChainHeadEvent, 1)
	sub := w.chain.SubscribeChainHeadEvent(changes)
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-changes:
			cancel()
		case <-sub.Err():
			cancel()
		case <-w.exitCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	defer func() { cancel(); sub.Unsubscribe(); <-done }()
	if w.chain.CurrentBlock().Hash() != parent.Hash() {
		return errors.New("miner: enrollment parent is no longer canonical")
	}
	if err := p.Prepare(ctx, types.CopyHeader(parent)); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.chain.CurrentBlock().Hash() != parent.Hash() {
		return errors.New("miner: enrollment parent changed during preparation")
	}
	w.enrollmentMu.Lock()
	w.enrollmentReady = parent.Hash()
	w.enrollmentMu.Unlock()
	return nil
}

func (w *worker) enrollmentCanSeal(parent common.Hash) bool {
	w.enrollmentMu.RLock()
	defer w.enrollmentMu.RUnlock()
	return w.enrollmentPreparer == nil || (w.enrollmentReady == parent && w.chain.CurrentBlock().Hash() == parent)
}

func (w *worker) hasEnrollmentPreparer() bool {
	w.enrollmentMu.RLock()
	defer w.enrollmentMu.RUnlock()
	return w.enrollmentPreparer != nil
}
