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
	"github.com/cryptoecc/WorldLand/core/state"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
	secp256k1 "github.com/cryptoecc/WorldLand/crypto/secp256k1"
	"github.com/cryptoecc/WorldLand/log"
	"github.com/cryptoecc/WorldLand/metrics"
	"github.com/cryptoecc/WorldLand/rpc"
	"golang.org/x/crypto/sha3"
)

// ECC is the VCT consensus engine: ECCPoW (LDPC) + secp256k1-VRF-based eligibility.
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

	// chainID for domain-separated mining signatures and powSeed
	chainID *big.Int

	lock      sync.Mutex
	closeOnce sync.Once
}

// chainIDBytes returns a 32-byte big-endian chain ID, or zeros if not configured.
func (ecc *ECC) chainIDBytes() []byte {
	ecc.lock.Lock()
	defer ecc.lock.Unlock()
	b := make([]byte, 32)
	if ecc.chainID != nil {
		ecc.chainID.FillBytes(b)
	}
	return b
}

// computeMiningSigMsg returns Keccak256(VCT_MINE || chainId || sealHash || nonce_LE8).
// This is the pre-WIP-6 message that the miner signs per ECCPoW nonce trial.
func computeMiningSigMsg(chainIDBytes, sealHash []byte, nonce uint64) []byte {
	msg := make([]byte, 8+32+32+8)
	copy(msg[:8], "VCT_MINE")
	copy(msg[8:40], chainIDBytes)
	copy(msg[40:72], sealHash)
	binary.LittleEndian.PutUint64(msg[72:80], nonce)
	return crypto.Keccak256(msg)
}

// computeMiningSigMsgVCT returns
// Keccak256(VCT_MINE || sealHash || vrfOutput || nonce_LE8).
// The verified VRF output binds each authorization to the eligibility result.
func computeMiningSigMsgVCT(sealHash []byte, vrfOutput [32]byte, nonce uint64) []byte {
	msg := make([]byte, 8+32+32+8)
	copy(msg[:8], "VCT_MINE")
	copy(msg[8:40], sealHash)
	copy(msg[40:72], vrfOutput[:])
	binary.LittleEndian.PutUint64(msg[72:80], nonce)
	return crypto.Keccak256(msg)
}

// computePowSeedVCT returns
// Keccak256(VCT_ECCPOW || sealHash || vrfOutput || nonce_LE8 || signature).
//
// The serialized VRF proof is excluded in favor of its unique semantic output.
// The ECDSA signature is included deliberately so an external miner needs a
// fresh account authorization before evaluating each (nonce, signature) work
// trial. ECDSA signatures are not unique, so the consensus work trial is the
// pair (nonce, signature), not the nonce alone.
func computePowSeedVCT(sealHash []byte, vrfOutput [32]byte, nonce uint64, signature []byte) []byte {
	raw := make([]byte, 10+32+32+8+len(signature))
	copy(raw[:10], "VCT_ECCPOW")
	copy(raw[10:42], sealHash)
	copy(raw[42:74], vrfOutput[:])
	binary.LittleEndian.PutUint64(raw[74:82], nonce)
	copy(raw[82:], signature)
	return crypto.Keccak256(raw)
}

// computeLegacyPowSeed returns the pre-VCT ECCPoW seed input:
// sealHash || nonce_LE8. The LDPC verifier applies Keccak512 to this raw seed.
func computeLegacyPowSeed(sealHash []byte, nonce uint64) []byte {
	raw := make([]byte, 32+8)
	copy(raw[:32], sealHash)
	binary.LittleEndian.PutUint64(raw[32:40], nonce)
	return raw
}

// computeVRFMsg returns the WIP-6 VRF input message:
// VCT_VRF || chainId (32 bytes) || phash_{h-1} (32 bytes) || h (8 bytes BE).
func computeVRFMsg(chainIDBytes, parentHash []byte, blockNumber uint64) []byte {
	msg := make([]byte, 7+32+32+8)
	copy(msg[:7], "VCT_VRF")
	copy(msg[7:39], chainIDBytes)
	copy(msg[39:71], parentHash)
	binary.BigEndian.PutUint64(msg[71:79], blockNumber)
	return msg
}

type Mode uint

const (
	epochLength = 30000 // blocks per epoch for seed hash (DAG legacy)

	// VCT eligibility parameters
	EligibilityEpochLength  = 100 // blocks per eligibility epoch
	EligibilitySeedLookback = 10  // blocks before epoch boundary for seed (fork resistance)

	ModeNormal Mode = iota
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

// -- Eligibility helpers -------------------------------------------------------

// EligibilityEpoch returns the eligibility epoch for a given block number.
func EligibilityEpoch(blockNumber uint64) uint64 {
	return blockNumber / EligibilityEpochLength
}

// EligibilityEpochStartBlock returns the first block of an epoch.
func EligibilityEpochStartBlock(epoch uint64) uint64 {
	return epoch * EligibilityEpochLength
}

// GetEligibilitySeedBlockNumber returns the block number whose hash is used as VRF input.
// Uses EligibilitySeedLookback before the epoch boundary to resist fork grinding.
func GetEligibilitySeedBlockNumber(blockNumber uint64) uint64 {
	epoch := EligibilityEpoch(blockNumber)
	if epoch == 0 {
		return 0
	}
	epochStart := EligibilityEpochStartBlock(epoch)
	if epochStart > EligibilitySeedLookback {
		return epochStart - EligibilitySeedLookback
	}
	return 0
}

// GetEligibilitySeedHash returns the block hash used as VRF message for eligibility.
func (ecc *ECC) GetEligibilitySeedHash(chain consensus.ChainHeaderReader, blockNumber uint64) common.Hash {
	seedBlockNum := GetEligibilitySeedBlockNumber(blockNumber)
	header := chain.GetHeaderByNumber(seedBlockNum)
	if header == nil {
		log.Warn("VCT: eligibility seed block unavailable", "needBlock", seedBlockNum, "forBlock", blockNumber)
		return common.Hash{}
	}
	return header.Hash()
}

// IsEligibleForBlock checks VCT eligibility for blockNumber.
// parentHash is the ParentHash of the block being mined.
// Returns (eligible, proofBytes, error).
func (ecc *ECC) IsEligibleForBlock(chain consensus.ChainHeaderReader, blockNumber uint64, parentHash common.Hash, threshold *big.Int) (bool, []byte, error) {
	ecc.lock.Lock()
	defer ecc.lock.Unlock()

	if len(ecc.vrfSecKey) == 0 || len(ecc.vrfPubKey) == 0 {
		return false, nil, errors.New("VCT: VRF keys not configured")
	}

	var msg []byte
	if chain.Config().IsVCT(new(big.Int).SetUint64(blockNumber)) {
		// WIP-6: VRF message = VCT_VRF || chainId || phash_{h-1} || h
		chainIDBytes := make([]byte, 32)
		if ecc.chainID != nil {
			ecc.chainID.FillBytes(chainIDBytes)
		}
		msg = computeVRFMsg(chainIDBytes, parentHash.Bytes(), blockNumber)
	} else {
		seedHash := ecc.GetEligibilitySeedHash(chain, blockNumber)
		if seedHash == (common.Hash{}) {
			return false, nil, errors.New("VCT: could not get eligibility seed hash")
		}
		msg = seedHash.Bytes()
	}

	proof, _, err := VRFProve(ecc.vrfSecKey, ecc.vrfPubKey, msg)
	if err != nil {
		return false, nil, fmt.Errorf("VCT: VRF prove failed: %w", err)
	}

	output, err := VRFOutputFromProof(proof)
	if err != nil {
		return false, nil, fmt.Errorf("VCT: VRF output extraction failed: %w", err)
	}
	eligible := EligibilityPassesWithBase(output, threshold, 0)
	log.Info("VCT eligibility", "block", blockNumber, "epoch", EligibilityEpoch(blockNumber), "threshold", threshold, "eligible", eligible)
	return eligible, proof, nil
}

// VerifyProposerEligibility implements consensus.ProposerVerifier.
// It enforces WIP-6 S0 after VCTBlock: the proposer's balance at parent state
// must meet the configured minimum.
func (ecc *ECC) VerifyProposerEligibility(chain consensus.ChainHeaderReader, header, parent *types.Header, parentState *state.StateDB) error {
	if !chain.Config().IsVCT(header.Number) {
		return nil
	}
	vctCfg := chain.Config().Vct
	if vctCfg == nil {
		return nil
	}
	if parentState == nil {
		return errors.New("VCT: parent state required for S0 proposer eligibility")
	}
	s0 := vctCfg.MinEligibleBalanceAt(header.Number)
	if s0.Sign() == 0 {
		return nil
	}
	balance := parentState.GetBalance(header.Coinbase)
	if balance.Cmp(s0) < 0 {
		return fmt.Errorf("VCT: proposer %s balance %s wei < S0 %s wei at block %d",
			header.Coinbase.Hex(), balance.String(), s0.String(), header.Number.Uint64())
	}
	return nil
}

// EnsureVRFKeys verifies that the account key has been registered for the given
// coinbase via SetVRFKey. Mining without an unlocked account is rejected so that
// the fake address-derived key can never be used silently.
func (ecc *ECC) EnsureVRFKeys(coinbase common.Address) error {
	ecc.lock.Lock()
	defer ecc.lock.Unlock()

	if ecc.vrfCoinbase == coinbase && len(ecc.vrfSecKey) > 0 && len(ecc.vrfPubKey) > 0 {
		return nil
	}
	return fmt.Errorf("VCT: account key not set for coinbase %s; unlock the account with --unlock before mining", coinbase.Hex())
}

// SetVRFKey sets an explicit secp256k1 private key (32 bytes) as the VRF key.
// The public key and vrfCoinbase are derived automatically, so EnsureVRFKeys
// will not overwrite this key when the miner's coinbase matches.
func (ecc *ECC) SetVRFKey(seckey []byte) error {
	pubkey, err := secp256k1.VRFPubkeyFromSeckey(seckey)
	if err != nil {
		return fmt.Errorf("VCT: invalid VRF private key: %w", err)
	}
	prv, err := crypto.ToECDSA(seckey)
	if err != nil {
		return fmt.Errorf("VCT: cannot parse private key: %w", err)
	}
	addr := crypto.PubkeyToAddress(prv.PublicKey)

	ecc.lock.Lock()
	defer ecc.lock.Unlock()
	ecc.vrfSecKey = make([]byte, 32)
	copy(ecc.vrfSecKey, seckey)
	ecc.vrfPubKey = pubkey
	ecc.vrfCoinbase = addr
	return nil
}

// -- Legacy LDPC mining helpers ------------------------------------------------

// Deprecated: this helper uses the legacy sealHash||nonce seed path and is not
// part of the WIP-6 VCT mining pipeline. New VCT code must use mine/mine_seoul,
// which bind each ECCPoW trial to the verified VRF output and a per-trial
// account authorization signature.
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

// Deprecated: this helper uses the legacy Seoul sealHash||nonce seed path and is
// not part of the WIP-6 VCT mining pipeline. New VCT code must use mine_seoul,
// which selects the correct seed path from the fork phase.
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
