//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"time"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/consensus"
	"github.com/cryptoecc/WorldLand/consensus/misc"
	"github.com/cryptoecc/WorldLand/core/state"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/log"
	"github.com/cryptoecc/WorldLand/params"
	"github.com/cryptoecc/WorldLand/rlp"
	"github.com/cryptoecc/WorldLand/trie"
	mapset "github.com/deckarep/golang-set"
	"golang.org/x/crypto/sha3"
)

// VCT network block reward: 20 WL per block (matches ECCBeta)
var (
	VCTBlockReward      = new(big.Int).Mul(big.NewInt(20), big.NewInt(1e+18))
	VCTTreasuryAddress  = common.HexToAddress("0x4C7dE6771DC602176b25fD4E1ae5550A3eAa06dF")
	VCT_HALVING_INTERVAL = uint64(12614400)

	FrontierBlockReward       = big.NewInt(5e+18)
	ByzantiumBlockReward      = big.NewInt(3e+18)
	ConstantinopleBlockReward = big.NewInt(2e+18)
	WorldLandBlockReward      = big.NewInt(4e+18)

	HALVING_INTERVAL  = uint64(6307200)
	MATURITY_INTERVAL = uint64(3153600)

	SumRewardUntilMaturity = big.NewInt(47304000)
	MaxHalving             = int64(4)

	maxUncles                     = 2
	allowedFutureBlockTimeSeconds = int64(15)
)

var (
	errLargeBlockTime    = errors.New("timestamp too big")
	errZeroBlockTime     = errors.New("timestamp equals parent's")
	errTooManyUncles     = errors.New("too many uncles")
	errDuplicateUncle    = errors.New("duplicate uncle")
	errUncleIsAncestor   = errors.New("uncle is ancestor")
	errDanglingUncle     = errors.New("uncle's parent is not ancestor")
	errInvalidDifficulty = errors.New("non-positive difficulty")
	errInvalidMixDigest  = errors.New("invalid mix digest")
	errInvalidPoW        = errors.New("invalid proof-of-work")
)

func (ecc *ECC) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

func (ecc *ECC) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	if ecc.config.PowMode == ModeFullFake {
		return nil
	}
	number := header.Number.Uint64()
	if chain.GetHeader(header.Hash(), number) != nil {
		return nil
	}
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	return ecc.verifyHeader(chain, header, parent, false, seal, time.Now().Unix())
}

func (ecc *ECC) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	if ecc.config.PowMode == ModeFullFake || len(headers) == 0 {
		abort, results := make(chan struct{}), make(chan error, len(headers))
		for range headers {
			results <- nil
		}
		return abort, results
	}
	workers := runtime.GOMAXPROCS(0)
	if len(headers) < workers {
		workers = len(headers)
	}
	var (
		inputs  = make(chan int)
		done    = make(chan int, workers)
		errs    = make([]error, len(headers))
		abort   = make(chan struct{})
		unixNow = time.Now().Unix()
	)
	for i := 0; i < workers; i++ {
		go func() {
			for index := range inputs {
				errs[index] = ecc.verifyHeaderWorker(chain, headers, seals, index, unixNow)
				done <- index
			}
		}()
	}
	errorsOut := make(chan error, len(headers))
	go func() {
		defer close(inputs)
		var (
			in, out = 0, 0
			checked = make([]bool, len(headers))
			ch      = inputs
		)
		for {
			select {
			case ch <- in:
				if in++; in == len(headers) {
					ch = nil
				}
			case index := <-done:
				for checked[index] = true; checked[out]; out++ {
					errorsOut <- errs[out]
					if out == len(headers)-1 {
						return
					}
				}
			case <-abort:
				return
			}
		}
	}()
	return abort, errorsOut
}

func (ecc *ECC) verifyHeaderWorker(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool, index int, unixNow int64) error {
	var parent *types.Header
	if index == 0 {
		parent = chain.GetHeader(headers[0].ParentHash, headers[0].Number.Uint64()-1)
	} else if headers[index-1].Hash() == headers[index].ParentHash {
		parent = headers[index-1]
	}
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	return ecc.verifyHeader(chain, headers[index], parent, false, seals[index], unixNow)
}

func (ecc *ECC) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if ecc.config.PowMode == ModeFullFake {
		return nil
	}
	if len(block.Uncles()) > maxUncles {
		return errTooManyUncles
	}
	if len(block.Uncles()) == 0 {
		return nil
	}
	uncles, ancestors := mapset.NewSet(), make(map[common.Hash]*types.Header)
	number, parent := block.NumberU64()-1, block.ParentHash()
	for i := 0; i < 7; i++ {
		anc := chain.GetHeader(parent, number)
		if anc == nil {
			break
		}
		ancestors[parent] = anc
		if anc.UncleHash != types.EmptyUncleHash {
			ab := chain.GetBlock(parent, number)
			if ab != nil {
				for _, u := range ab.Uncles() {
					uncles.Add(u.Hash())
				}
			}
		}
		parent, number = anc.ParentHash, number-1
	}
	ancestors[block.Hash()] = block.Header()
	uncles.Add(block.Hash())

	for _, uncle := range block.Uncles() {
		h := uncle.Hash()
		if uncles.Contains(h) {
			return errDuplicateUncle
		}
		uncles.Add(h)
		if ancestors[h] != nil {
			return errUncleIsAncestor
		}
		if ancestors[uncle.ParentHash] == nil || uncle.ParentHash == block.ParentHash() {
			return errDanglingUncle
		}
		if err := ecc.verifyHeader(chain, uncle, ancestors[uncle.ParentHash], true, true, time.Now().Unix()); err != nil {
			return err
		}
	}
	return nil
}

func (ecc *ECC) verifyHeader(chain consensus.ChainHeaderReader, header, parent *types.Header, uncle bool, seal bool, unixNow int64) error {
	if uint64(len(header.Extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("extra-data too long: %d > %d", len(header.Extra), params.MaximumExtraDataSize)
	}
	if !uncle {
		if header.Time > uint64(unixNow+allowedFutureBlockTimeSeconds) {
			return consensus.ErrFutureBlock
		}
	}
	if header.Time <= parent.Time {
		return errZeroBlockTime
	}
	expectDiff := ecc.CalcDifficulty(chain, header.Time, parent)
	if expectDiff.Cmp(header.Difficulty) != 0 {
		return fmt.Errorf("invalid vct difficulty: have %v, want %v", header.Difficulty, expectDiff)
	}
	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}
	if !chain.Config().IsLondon(header.Number) {
		if header.BaseFee != nil {
			return fmt.Errorf("invalid baseFee before fork: have %d, want nil", header.BaseFee)
		}
		if err := misc.VerifyGaslimit(parent.GasLimit, header.GasLimit); err != nil {
			return err
		}
	} else if err := misc.VerifyEip1559Header(chain.Config(), parent, header); err != nil {
		return err
	}
	if diff := new(big.Int).Sub(header.Number, parent.Number); diff.Cmp(big.NewInt(1)) != 0 {
		return consensus.ErrInvalidNumber
	}
	if seal {
		isVCT := chain.Config().IsVCT(header.Number)
		if err := ecc.verifySeal(chain, header); err != nil {
			return err
		}
		if err := ecc.verifyVRFProof(chain, header, parent); err != nil {
			return err
		}
		if err := ecc.verifyMiningSig(header, ecc.SealHash(header).Bytes(), isVCT); err != nil {
			return err
		}
	}
	if err := misc.VerifyDAOHeaderExtraData(chain.Config(), header); err != nil {
		return err
	}
	if err := misc.VerifyForkHashes(chain.Config(), header, uncle); err != nil {
		return err
	}
	return nil
}

// verifyVRFProof checks the secp256k1 VRF proof stored in the block header.
// parent must be non-nil; it is used to compute Δt for progressive timeout verification.
func (ecc *ECC) verifyVRFProof(chain consensus.ChainHeaderReader, header, parent *types.Header) error {
	if len(header.VRFProof) == 0 {
		return errors.New("VCT: VRF proof missing")
	}
	if len(header.VRFPublicKey) != 33 {
		return fmt.Errorf("VCT: VRF public key must be 33 bytes, got %d", len(header.VRFPublicKey))
	}

	blockNumber := header.Number.Uint64()

	var msg []byte
	var deltaT uint64 // elapsed seconds since parent; used for progressive timeout (WIP-6 only)
	if chain.Config().IsVCT(header.Number) {
		// WIP-6: verify Address(VRFPublicKey) == Coinbase
		pub, err := crypto.DecompressPubkey(header.VRFPublicKey)
		if err != nil {
			return fmt.Errorf("VCT: failed to decompress VRF public key: %w", err)
		}
		vrfAddr := crypto.PubkeyToAddress(*pub)
		if vrfAddr != header.Coinbase {
			return fmt.Errorf("VCT: VRF public key address %v != coinbase %v", vrfAddr, header.Coinbase)
		}
		// WIP-6: VRF message = VCT_VRF || chainId || phash_{h-1} || h
		chainIDBytes := ecc.chainIDBytes()
		msg = computeVRFMsg(chainIDBytes, header.ParentHash.Bytes(), blockNumber)

		// Compute Δt from block timestamps for progressive timeout sortition check.
		// parent is always non-nil here (guaranteed by verifyHeader).
		if header.Time > parent.Time {
			deltaT = header.Time - parent.Time
		}
	} else {
		seedHash := ecc.GetSortitionSeedHash(chain, blockNumber)
		if seedHash == (common.Hash{}) {
			log.Warn("VCT: VRF verification failed - seed block unavailable", "block", blockNumber)
			return errors.New("VCT: sortition seed block unavailable")
		}
		msg = seedHash.Bytes()
	}

	if _, err := VRFVerify(header.VRFPublicKey, header.VRFProof, msg); err != nil {
		return fmt.Errorf("VCT: VRF proof invalid: %w", err)
	}

	// WIP-6: time-dependent threshold (progressive timeout liveness guarantee).
	// Pre-VCT: fixed threshold.
	if chain.Config().IsVCT(header.Number) {
		if !CheckSortitionWithTime(header.VRFProof, deltaT) {
			return fmt.Errorf("VCT: VRF proof does not pass sortition threshold (Δt=%d s)", deltaT)
		}
	} else {
		if !CheckSortition(header.VRFProof) {
			return errors.New("VCT: VRF proof does not pass sortition threshold")
		}
	}

	log.Debug("VCT: VRF proof verified", "block", blockNumber, "epoch", SortitionEpoch(blockNumber), "deltaT", deltaT)
	return nil
}

func (ecc *ECC) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	next := new(big.Int).Add(parent.Number, big1)
	switch {
	case chain.Config().IsAnnapurna(next):
		return calcDifficultyAnnapurna(chain, time, parent)
	case chain.Config().IsSeoul(next):
		return calcDifficultySeoul(chain, time, parent)
	default:
		return calcDifficultyFrontier(time, parent)
	}
}

var (
	expDiffPeriod = big.NewInt(100000)
	big1          = big.NewInt(1)
	big2          = big.NewInt(2)
	big9          = big.NewInt(9)
	big10         = big.NewInt(10)
	bigMinus99    = big.NewInt(-99)
)

func makeDifficultyCalculator(bombDelay *big.Int) func(time uint64, parent *types.Header) *big.Int {
	return MakeLDPCDifficultyCalculator()
}

func calcDifficultyFrontier(time uint64, parent *types.Header) *big.Int {
	return MakeLDPCDifficultyCalculator()(time, parent)
}

func calcDifficultySeoul(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return MakeLDPCDifficultyCalculator_Seoul()(time, parent)
}

func calcDifficultyAnnapurna(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return MakeLDPCDifficultyCalculatorAnnapurna()(time, parent)
}

var FrontierDifficultyCalculator = calcDifficultyFrontier
var DynamicDifficultyCalculator = makeDifficultyCalculator

func (ecc *ECC) verifySeal(chain consensus.ChainHeaderReader, header *types.Header) error {
	if ecc.config.PowMode == ModeFake || ecc.config.PowMode == ModeFullFake {
		time.Sleep(ecc.fakeDelay)
		if ecc.fakeFail == header.Number.Uint64() {
			return errInvalidPoW
		}
		return nil
	}
	if ecc.shared != nil {
		return ecc.shared.verifySeal(chain, header)
	}
	if header.Difficulty.Sign() <= 0 {
		return errInvalidDifficulty
	}

	if chain.Config().ChainID != nil {
		ecc.lock.Lock()
		ecc.chainID = chain.Config().ChainID
		ecc.lock.Unlock()
	}

	sealHash := ecc.SealHash(header).Bytes()
	var powSeed []byte
	if chain.Config().IsVCT(header.Number) {
		powSeed = computePowSeedVCT(sealHash, header.Nonce.Uint64(), header.VRFSignature)
	} else {
		powSeed = computePowSeed(ecc.chainIDBytes(), sealHash, header.Nonce.Uint64(), header.VRFSignature)
	}

	var (
		digest []byte
		flag   bool
	)
	if chain.Config().IsSeoul(header.Number) {
		flag, _, _, digest = VCTVerifyOptimizedDecodingSeoul(header, powSeed)
	} else {
		flag, _, _, digest = VCTVerifyOptimizedDecoding(header, powSeed)
	}

	encodedDigest := common.BytesToHash(digest)
	if !bytes.Equal(header.MixDigest[:], encodedDigest[:]) {
		return errInvalidMixDigest
	}
	if !flag {
		return errInvalidPoW
	}
	return nil
}

func (ecc *ECC) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Difficulty = ecc.CalcDifficulty(chain, header.Time, parent)
	if chain.Config().ChainID != nil {
		ecc.lock.Lock()
		ecc.chainID = chain.Config().ChainID
		ecc.lock.Unlock()
	}
	return nil
}

func (ecc *ECC) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header) {
	accumulateRewards(chain.Config(), state, header, uncles)
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
}

func (ecc *ECC) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	ecc.Finalize(chain, header, state, txs, uncles)
	return types.NewBlock(header, txs, uncles, receipts, trie.NewStackTrie(nil)), nil
}

func (ecc *ECC) SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	// VCT_SEAL domain prefix + chain ID for domain separation.
	hasher.Write([]byte("VCT_SEAL"))
	hasher.Write(ecc.chainIDBytes())
	// Block template fields only. Excluded (all set during Seal/mining):
	//   Nonce, MixDigest, Codeword — PoW outputs
	//   VRFPublicKey, VRFProof     — filled in by Seal() before mining starts
	//   VRFSignature               — per-nonce mining signature
	//   CodeLength                 — derived from difficulty by mine_seoul and written back
	enc := []interface{}{
		header.ParentHash, header.UncleHash, header.Coinbase,
		header.Root, header.TxHash, header.ReceiptHash,
		header.Bloom, header.Difficulty, header.Number,
		header.GasLimit, header.GasUsed, header.Time, header.Extra,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	rlp.Encode(hasher, enc)
	hasher.Sum(hash[:0])
	return hash
}

// verifyMiningSig checks that header.VRFSignature is a valid per-nonce mining
// signature by the block's coinbase: ECRecover(σ_ν, m_ν) = coinbase.
// WIP-6 (isVCT=true): m_ν = Keccak256(VCT_MINE || sealHash || nonce).
// Pre-WIP-6:          m_ν = Keccak256(VCT_MINE || chainId || sealHash || nonce).
func (ecc *ECC) verifyMiningSig(header *types.Header, sealHash []byte, isVCT bool) error {
	if len(header.VRFSignature) != 65 {
		return fmt.Errorf("VCT: VRFSignature must be 65 bytes, got %d", len(header.VRFSignature))
	}
	var msgHash []byte
	if isVCT {
		msgHash = computeMiningSigMsgVCT(sealHash, header.Nonce.Uint64())
	} else {
		msgHash = computeMiningSigMsg(ecc.chainIDBytes(), sealHash, header.Nonce.Uint64())
	}
	pub, err := crypto.SigToPub(msgHash, header.VRFSignature)
	if err != nil {
		return fmt.Errorf("VCT: mining sig recovery failed: %w", err)
	}
	addr := crypto.PubkeyToAddress(*pub)
	if addr != header.Coinbase {
		return fmt.Errorf("VCT: mining sig signer %v != coinbase %v", addr, header.Coinbase)
	}
	return nil
}

var (
	big8  = big.NewInt(8)
	big32 = big.NewInt(32)
)

func accumulateRewards(config *params.ChainConfig, state *state.StateDB, header *types.Header, uncles []*types.Header) {
	blockReward := new(big.Int).Set(VCTBlockReward)

	reward := new(big.Int).Set(blockReward)
	r := new(big.Int)
	for _, uncle := range uncles {
		r.Add(uncle.Number, big8)
		r.Sub(r, header.Number)
		r.Mul(r, blockReward)
		r.Div(r, big8)
		state.AddBalance(uncle.Coinbase, r)
		r.Div(blockReward, big32)
		reward.Add(reward, r)
	}

	// 20% to treasury
	treasury := new(big.Int).Div(reward, big.NewInt(5))
	state.AddBalance(VCTTreasuryAddress, treasury)
	state.AddBalance(header.Coinbase, new(big.Int).Sub(reward, treasury))
}
