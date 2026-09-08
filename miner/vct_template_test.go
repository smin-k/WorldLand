//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package miner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/cryptoecc/WorldLand/common"
	vct "github.com/cryptoecc/WorldLand/consensus/VCT"
	"github.com/cryptoecc/WorldLand/consensus/beacon"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/core"
	"github.com/cryptoecc/WorldLand/core/rawdb"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/core/vm"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
	"github.com/cryptoecc/WorldLand/event"
	"github.com/cryptoecc/WorldLand/params"
)

// A software signer is a cryptographic test fixture, never a TPM substitute in
// deployment. The sealer, ECCPoW, worker, EVM and peer import are production code.
type templateTestSigner struct{ key *ecdsa.PrivateKey }

func (s *templateTestSigner) PublicKey() []byte {
	return elliptic.Marshal(elliptic.P256(), s.key.X, s.key.Y)
}
func (s *templateTestSigner) Close() error { return nil }
func (s *templateTestSigner) SignDigest(digest []byte) ([]byte, error) {
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, digest)
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, 64)
	r.FillBytes(encoded[:32])
	ss.FillBytes(encoded[32:])
	return tpmwork.NormalizeSignature(encoded)
}

func TestVCTTimeoutTemplateExecutesBeforeSealAndImports(t *testing.T) {
	// Real ECCPoW at its existing Seoul floor keeps this regression fast.
	previous := vct.VCTMinimumDifficulty
	vct.VCTMinimumDifficulty = big.NewInt(1023)
	defer func() { vct.VCTMinimumDifficulty = previous }()
	cfg := *params.AllEthashProtocolChanges
	cfg.ChainID = big.NewInt(91510)
	cfg.WorldlandBlock, cfg.SeoulBlock, cfg.AnnapurnaBlock = big.NewInt(0), big.NewInt(0), big.NewInt(0)
	cfg.VCTBlock, cfg.TPMGatedBlock = big.NewInt(1), big.NewInt(1)
	cfg.Vct = &params.VctConfig{SeedDelay: 1, InitialEligibilityThreshold: big.NewInt(1)}
	secret := make([]byte, 32)
	secret[31] = 1
	account, err := crypto.ToECDSA(secret)
	if err != nil {
		t.Fatal(err)
	}
	coinbase := crypto.PubkeyToAddress(account.PublicKey)
	x, y := elliptic.P256().ScalarBaseMult([]byte{1})
	workSigner := &templateTestSigner{&ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: big.NewInt(1)}}
	nullifier := crypto.Keccak256Hash([]byte("template regression test device"))
	did := tpmregistry.DeriveConsensusIdentity(cfg.ChainID, tpmregistry.DefaultRegistryAddress, nullifier)
	storage, err := tpmregistry.PredeployStorage(tpmregistry.PredeployConfig{
		Address: tpmregistry.DefaultRegistryAddress, Governor: coinbase, FixedCollateral: new(big.Int),
		RegistrationTTL: 100, ActivationDelay: 1, ProducerSlotCount: 3, ProducerThreshold: 3,
		ProducerResponseWindow: 20, ProducerPolicyDigest: crypto.Keccak256Hash([]byte("test policy")),
	})
	if err != nil {
		t.Fatal(err)
	}
	vrfHash, err := tpmregistry.VRFKeyHash(crypto.FromECDSAPub(&account.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := tpmregistry.AddBootstrapRegistration(storage, tpmregistry.BootstrapRegistration{
		DID: did, Controller: coinbase, WorkKeyHash: crypto.Keccak256Hash(workSigner.PublicKey()),
		VRFKeyHash: vrfHash, ProfileHash: crypto.Keccak256Hash([]byte("test profile")), DeviceNullifier: nullifier,
	}); err != nil {
		t.Fatal(err)
	}
	code, err := tpmregistry.RegistryRuntimeCode()
	if err != nil {
		t.Fatal(err)
	}
	contract := common.HexToAddress("0x1234")
	genesis := &core.Genesis{Config: &cfg, Timestamp: 1700000000, Difficulty: big.NewInt(1023), GasLimit: 15000000,
		Alloc: core.GenesisAlloc{
			coinbase:                           {Balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(20), nil)},
			tpmregistry.DefaultRegistryAddress: {Balance: new(big.Int), Code: code, Storage: storage},
			// Store TIMESTAMP at slot0 and DIFFICULTY at slot1.
			contract: {Balance: new(big.Int), Code: []byte{0x42, 0x60, 0x00, 0x55, 0x44, 0x60, 0x01, 0x55, 0x00}},
		},
	}
	db := rawdb.NewMemoryDatabase()
	genesis.MustCommit(db)
	inner := vct.New(vct.Config{PowMode: vct.ModeNormal}, nil, false)
	defer inner.Close()
	inner.SetThreads(1)
	if err := inner.SetVRFKey(secret); err != nil {
		t.Fatal(err)
	}
	if err := inner.SetTPMWorkSigner(did, workSigner); err != nil {
		t.Fatal(err)
	}
	engine := beacon.New(inner) // Exercise the same wrapper used by the client.
	chain, err := core.NewBlockChain(db, nil, genesis, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	pool := core.NewTxPool(testTxPoolConfig, &cfg, chain)
	defer pool.Stop()
	backend := &testWorkerBackend{db: db, chain: chain, txPool: pool, genesis: genesis}
	w := newWorker(testConfig, &cfg, engine, backend, new(event.TypeMux), nil, false)
	defer w.close()
	w.setEtherbase(coinbase)
	work, err := w.prepareWork(&generateParams{timestamp: genesis.Timestamp + 1, coinbase: coinbase})
	if err != nil {
		t.Fatal(err)
	}
	defer work.discard()
	if work.header.Time <= genesis.Timestamp+1 {
		t.Fatal("fixture must exercise timeout, not immediate eligibility")
	}
	// A future template is cancellable without blocking the worker task loop.
	future, err := w.prepareWork(&generateParams{timestamp: uint64(time.Now().Unix()) + 60, coinbase: coinbase})
	if err != nil {
		t.Fatal(err)
	}
	defer future.discard()
	futureBlock, err := engine.FinalizeAndAssemble(chain, future.header, future.state, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cancelFuture := make(chan struct{})
	deferredResults := make(chan *types.Block, 1)
	started := time.Now()
	if err := engine.Seal(chain, futureBlock, deferredResults, cancelFuture); err != nil {
		t.Fatal(err)
	}
	close(cancelFuture)
	if time.Since(started) > time.Second {
		t.Fatal("future Seal blocked the worker")
	}
	emptyEnv := work.copy()
	defer emptyEnv.discard()
	empty, err := engine.FinalizeAndAssemble(chain, emptyEnv.header, emptyEnv.state, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := types.SignTx(types.NewTransaction(0, contract, new(big.Int), 150000, big.NewInt(2*params.InitialBaseFee), nil), types.MakeSigner(&cfg, big.NewInt(1)), account)
	if err != nil {
		t.Fatal(err)
	}
	work.gasPool = new(core.GasPool).AddGas(work.header.GasLimit)
	work.state.Prepare(tx.Hash(), 0)
	if _, err := w.commitTransaction(work, tx); err != nil {
		t.Fatal(err)
	}
	block, err := engine.FinalizeAndAssemble(chain, work.header, work.state, work.txs, nil, work.receipts)
	if err != nil {
		t.Fatal(err)
	}
	if got := work.state.GetState(contract, common.Hash{}); got != common.BigToHash(new(big.Int).SetUint64(block.Time())) {
		t.Fatalf("EVM saw wrong timestamp: %s", got)
	}
	sealHash := engine.SealHash(block.Header())
	results := make(chan *types.Block, 1)
	stop := make(chan struct{})
	defer close(stop)
	if err := engine.Seal(chain, block, results, stop); err != nil {
		t.Fatal(err)
	}
	var sealed *types.Block
	select {
	case sealed = <-results:
	case <-time.After(30 * time.Second):
		t.Fatal("real ECCPoW sealing timed out")
	}
	if engine.SealHash(sealed.Header()) != sealHash || sealed.Time() != block.Time() || sealed.Root() != block.Root() {
		t.Fatal("Seal changed executed template")
	}
	if err := chain.Validator().ValidateState(sealed, emptyEnv.state, nil, 0); err == nil {
		t.Fatal("accepted another same-height task's state and receipts")
	}
	w.pendingMu.Lock()
	w.pendingTasks[engine.SealHash(empty.Header())] = &task{block: empty, state: emptyEnv.state}
	w.pendingTasks[sealHash] = &task{block: block, state: work.state, receipts: work.receipts, createdAt: time.Now()}
	w.pendingMu.Unlock()
	heads := make(chan core.ChainHeadEvent, 1)
	sub := chain.SubscribeChainHeadEvent(heads)
	defer sub.Unsubscribe()
	w.resultCh <- sealed
	select {
	case head := <-heads:
		if head.Block.Hash() != sealed.Hash() {
			t.Fatal("stored wrong result")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not accept exact sealed task")
	}
	peerDB := rawdb.NewMemoryDatabase()
	genesis.MustCommit(peerDB)
	peerInner := vct.New(vct.Config{PowMode: vct.ModeNormal}, nil, false)
	defer peerInner.Close()
	peer, err := core.NewBlockChain(peerDB, nil, genesis, nil, beacon.New(peerInner), vm.Config{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Stop()
	if _, err := peer.InsertChain([]*types.Block{sealed}); err != nil {
		t.Fatalf("independent peer rejected sealed timeout block: %v", err)
	}
	peerState, err := peer.State()
	if err != nil {
		t.Fatal(err)
	}
	if peerState.GetState(contract, common.Hash{}) != common.BigToHash(new(big.Int).SetUint64(sealed.Time())) || peerState.GetState(contract, common.HexToHash("0x01")) != common.BigToHash(sealed.Difficulty()) {
		t.Fatal("peer execution context diverged")
	}
}
