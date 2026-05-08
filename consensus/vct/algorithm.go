//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/consensus"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/log"
	"github.com/cryptoecc/WorldLand/metrics"
	"github.com/cryptoecc/WorldLand/rpc"
	"golang.org/x/crypto/sha3"
)

// ECC is the VCT consensus engine: ECCPoW (LDPC) + secp256k1 ECVRF sortition.
type ECC struct {
	config Config

	rand     *rand.Rand
	threads  int
	update   chan struct{}
	hashrate metrics.Meter
	remote   *remoteSealer

	workCh       chan *sealTask
	fetchWorkCh  chan *sealWork
	submitWorkCh chan *mineResult
	fetchRateCh  chan chan uint64
	submitRateCh chan *hashrate

	shared    *ECC
	fakeFail  uint64
	fakeDelay time.Duration

	// secp256k1 VRF key pair (32-byte seckey, 33-byte compressed pubkey)
	vrfSecKey   []byte
	vrfPubKey   []byte
	vrfCoinbase common.Address

	lock      sync.Mutex
	closeOnce sync.Once
}

type Mode uint

const (
	epochLength = 30000 // blocks per epoch for seed hash (DAG legacy)

	// VRF sortition parameters
	SortitionEpochLength  = 100 // blocks per sortition epoch
	SortitionSeedLookback = 10  // blocks before epoch boundary for seed (fork resistance)

	ModeNormal  Mode = iota
	ModeShared
	ModeTest
	ModeFake
	ModeFullFake
)

// Config holds VCT engine configuration.
type Config struct {
	PowMode    Mode
	NotifyFull bool
	Log        log.Logger `toml:"-"`
}

var (
	two256 = new(big.Int).Exp(big.NewInt(2), big.NewInt(256), big.NewInt(0))

	sharedECC         *ECC
	algorithmRevision = 2
)

func init() {
	sharedECC = New(Config{PowMode: ModeNormal}, nil, false)
}

type verifyParameters struct {
	n          uint64
	m          uint64
	wc         uint64
	wr         uint64
	seed       uint64
	outputWord []uint64
}

// New creates a VCT PoW engine and starts the remote mining goroutine.
func New(config Config, notify []string, noverify bool) *ECC {
	if config.Log == nil {
		config.Log = log.Root()
	}
	ecc := &ECC{
		config:       config,
		update:       make(chan struct{}),
		hashrate:     metrics.NewMeterForced(),
		workCh:       make(chan *sealTask),
		fetchWorkCh:  make(chan *sealWork),
		submitWorkCh: make(chan *mineResult),
		fetchRateCh:  make(chan chan uint64),
		submitRateCh: make(chan *hashrate),
	}
	if config.PowMode == ModeShared {
		ecc.shared = sharedECC
	}
	ecc.remote = startRemoteSealer(ecc, notify, noverify)
	return ecc
}

// NewTester creates a test-mode VCT engine.
func NewTester(notify []string, noverify bool) *ECC {
	ecc := &ECC{
		config:       Config{PowMode: ModeTest},
		update:       make(chan struct{}),
		hashrate:     metrics.NewMeterForced(),
		workCh:       make(chan *sealTask),
		fetchWorkCh:  make(chan *sealWork),
		submitWorkCh: make(chan *mineResult),
		fetchRateCh:  make(chan chan uint64),
		submitRateCh: make(chan *hashrate),
	}
	ecc.remote = startRemoteSealer(ecc, notify, noverify)
	return ecc
}

// NewFaker creates a VCT engine with fake PoW (accepts all blocks as valid).
func NewFaker() *ECC {
	return &ECC{config: Config{PowMode: ModeFake, Log: log.Root()}}
}

// NewFakeFailer creates a fake engine that fails for a specific block number.
func NewFakeFailer(fail uint64) *ECC {
	return &ECC{config: Config{PowMode: ModeFake, Log: log.Root()}, fakeFail: fail}
}

// NewFakeDelayer creates a fake engine that sleeps before returning.
func NewFakeDelayer(delay time.Duration) *ECC {
	return &ECC{config: Config{PowMode: ModeFake, Log: log.Root()}, fakeDelay: delay}
}

// NewFullFaker creates an engine that accepts everything without any checks.
func NewFullFaker() *ECC {
	return &ECC{config: Config{PowMode: ModeFullFake, Log: log.Root()}}
}

// Close shuts down the remote sealer.
func (ecc *ECC) Close() error {
	return ecc.StopRemoteSealer()
}

// StopRemoteSealer stops the remote sealer goroutine.
func (ecc *ECC) StopRemoteSealer() error {
	ecc.closeOnce.Do(func() {
		if ecc.remote == nil {
			return
		}
		close(ecc.remote.requestExit)
		<-ecc.remote.exitCh
	})
	return nil
}

// Threads returns the current mining thread count.
func (ecc *ECC) Threads() int {
	ecc.lock.Lock()
	defer ecc.lock.Unlock()
	return ecc.threads
}

// SetThreads updates the mining thread count.
func (ecc *ECC) SetThreads(threads int) {
	ecc.lock.Lock()
	defer ecc.lock.Unlock()
	if ecc.shared != nil {
		ecc.shared.SetThreads(threads)
		return
	}
	ecc.threads = threads
	select {
	case ecc.update <- struct{}{}:
	default:
	}
}

// Hashrate returns the combined local + remote hash rate.
func (ecc *ECC) Hashrate() float64 {
	var res = make(chan uint64, 1)
	select {
	case ecc.remote.fetchRateCh <- res:
	case <-ecc.remote.exitCh:
		return ecc.hashrate.Rate1()
	}
	return ecc.hashrate.Rate1() + float64(<-res)
}

// APIs exposes the mining RPC endpoints.
func (ecc *ECC) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{
		{Namespace: "eth", Version: "1.0", Service: &API{ecc}, Public: true},
		{Namespace: "vct", Version: "1.0", Service: &API{ecc}, Public: true},
	}
}

// ── Sortition helpers ─────────────────────────────────────────────────────────

// SortitionEpoch returns the sortition epoch for a given block number.
func SortitionEpoch(blockNumber uint64) uint64 {
	return blockNumber / SortitionEpochLength
}

// SortitionEpochStartBlock returns the first block of an epoch.
func SortitionEpochStartBlock(epoch uint64) uint64 {
	return epoch * SortitionEpochLength
}

// GetSortitionSeedBlockNumber returns the block number whose hash is used as VRF input.
// Uses SortitionSeedLookback before the epoch boundary to resist fork grinding.
func GetSortitionSeedBlockNumber(blockNumber uint64) uint64 {
	epoch := SortitionEpoch(blockNumber)
	if epoch == 0 {
		return 0
	}
	epochStart := SortitionEpochStartBlock(epoch)
	if epochStart > SortitionSeedLookback {
		return epochStart - SortitionSeedLookback
	}
	return 0
}

// GetSortitionSeedHash returns the block hash used as VRF message for sortition.
func (ecc *ECC) GetSortitionSeedHash(chain consensus.ChainHeaderReader, blockNumber uint64) common.Hash {
	seedBlockNum := GetSortitionSeedBlockNumber(blockNumber)
	header := chain.GetHeaderByNumber(seedBlockNum)
	if header == nil {
		log.Warn("VCT: sortition seed block unavailable", "needBlock", seedBlockNum, "forBlock", blockNumber)
		return common.Hash{}
	}
	return header.Hash()
}

// IsEligibleForBlock checks VRF sortition eligibility for blockNumber.
// Returns (eligible, proofBytes, error).
func (ecc *ECC) IsEligibleForBlock(chain consensus.ChainHeaderReader, blockNumber uint64) (bool, []byte, error) {
	ecc.lock.Lock()
	defer ecc.lock.Unlock()

	if len(ecc.vrfSecKey) == 0 || len(ecc.vrfPubKey) == 0 {
		return false, nil, errors.New("VCT: VRF keys not configured")
	}

	seedHash := ecc.GetSortitionSeedHash(chain, blockNumber)
	if seedHash == (common.Hash{}) {
		return false, nil, errors.New("VCT: could not get sortition seed hash")
	}

	// VRF message: "VCT_VRF" | chainId (not available here, use seedHash directly)
	msg := seedHash.Bytes()

	proof, _, err := VRFProve(ecc.vrfSecKey, ecc.vrfPubKey, msg)
	if err != nil {
		return false, nil, fmt.Errorf("VCT: VRF prove failed: %w", err)
	}

	eligible := CheckSortition(proof)
	log.Info("VCT sortition", "block", blockNumber, "epoch", SortitionEpoch(blockNumber), "eligible", eligible)
	return eligible, proof, nil
}

// EnsureVRFKeys checks whether VRF keys match coinbase and re-derives if not.
func (ecc *ECC) EnsureVRFKeys(coinbase common.Address) error {
	ecc.lock.Lock()
	defer ecc.lock.Unlock()

	if ecc.vrfCoinbase == coinbase && len(ecc.vrfSecKey) > 0 && len(ecc.vrfPubKey) > 0 {
		return nil
	}

	seckey, pubkey, err := DeriveVRFKeys(coinbase, nil)
	if err != nil {
		return fmt.Errorf("VCT: failed to derive VRF keys: %w", err)
	}
	ecc.vrfSecKey = seckey
	ecc.vrfPubKey = pubkey
	ecc.vrfCoinbase = coinbase
	log.Info("VCT: VRF keys derived", "coinbase", coinbase)
	return nil
}

// SetVRFKey sets an explicit secp256k1 private key (32 bytes) as the VRF key.
// The public key is derived automatically. Useful when the miner controls their own key.
func (ecc *ECC) SetVRFKey(seckey []byte) error {
	pubkey, err := VRFPubkeyFromSeckey(seckey)
	if err != nil {
		return fmt.Errorf("VCT: invalid VRF private key: %w", err)
	}
	ecc.lock.Lock()
	defer ecc.lock.Unlock()
	ecc.vrfSecKey = make([]byte, 32)
	copy(ecc.vrfSecKey, seckey)
	ecc.vrfPubKey = pubkey
	return nil
}

// ── LDPC mining helpers ───────────────────────────────────────────────────────

func RunOptimizedConcurrencyLDPC(header *types.Header, hash []byte) (bool, []int, []int, uint64, []byte) {
	var (
		LDPCNonce  uint64
		hashVector []int
		outputWord []int
		digest     []byte
		flag       bool
	)
	parameters, _ := setParameters(header)
	H := generateH(parameters)
	colInRow, rowInCol := generateQ(parameters, H)

	for i := 0; i < 64; i++ {
		nonce := generateRandomNonce()
		seed := make([]byte, 40)
		copy(seed, hash)
		binary.LittleEndian.PutUint64(seed[32:], nonce)
		seed = crypto.Keccak512(seed)

		hv := generateHv(parameters, seed)
		hv, ow, _ := OptimizedDecoding(parameters, hv, H, rowInCol, colInRow)
		if ok, _ := MakeDecision(header, colInRow, ow); ok {
			hashVector, outputWord, LDPCNonce, digest, flag = hv, ow, nonce, seed, true
			break
		}
	}
	return flag, hashVector, outputWord, LDPCNonce, digest
}

func RunOptimizedConcurrencyLDPC_Seoul(header *types.Header, hash []byte) (bool, []int, []int, uint64, []byte) {
	var (
		LDPCNonce  uint64
		hashVector []int
		outputWord []int
		digest     []byte
		flag       bool
	)
	parameters, _ := setParameters_Seoul(header)
	H := generateH(parameters)
	colInRow, rowInCol := generateQ(parameters, H)

	for i := 0; i < 64; i++ {
		nonce := generateRandomNonce()
		seed := make([]byte, 40)
		copy(seed, hash)
		binary.LittleEndian.PutUint64(seed[32:], nonce)
		seed = crypto.Keccak512(seed)

		hv := generateHv(parameters, seed)
		hv, ow, _ := OptimizedDecodingSeoul(parameters, hv, H, rowInCol, colInRow)
		if ok, _ := MakeDecision_Seoul(header, colInRow, ow); ok {
			hashVector, outputWord, LDPCNonce, digest, flag = hv, ow, nonce, seed, true
			break
		}
	}
	return flag, hashVector, outputWord, LDPCNonce, digest
}

// hasher / seedHash (kept for remote-sealer makeWork compatibility)
type hasher func(dest []byte, data []byte)

func makeHasher(h hash.Hash) hasher {
	type readerHash interface {
		hash.Hash
		Read([]byte) (int, error)
	}
	rh, ok := h.(readerHash)
	if !ok {
		panic("can't find Read method on hash")
	}
	outputLen := rh.Size()
	return func(dest []byte, data []byte) {
		rh.Reset()
		rh.Write(data)
		rh.Read(dest[:outputLen])
	}
}

func seedHash(block uint64) []byte {
	seed := make([]byte, 32)
	if block < epochLength {
		return seed
	}
	keccak256 := makeHasher(sha3.NewLegacyKeccak256())
	for i := 0; i < int(block/epochLength); i++ {
		keccak256(seed, seed)
	}
	return seed
}

func SeedHash(block uint64) []byte { return seedHash(block) }
