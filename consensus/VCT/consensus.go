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

// VCT network block reward: 20 WL per block.
var (
	VCTBlockReward       = new(big.Int).Mul(big.NewInt(20), big.NewInt(1e+18))
	VCTTreasuryAddress   = common.HexToAddress("0x4C7dE6771DC602176b25fD4E1ae5550A3eAa06dF")
	VCTMinimumDifficulty = big.NewInt(65536)

	FrontierBlockReward       = big.NewInt(5e+18)
	ByzantiumBlockReward      = big.NewInt(3e+18)
	ConstantinopleBlockReward = big.NewInt(2e+18)
	WorldLandBlockReward      = big.NewInt(4e+18)

	HALVING_INTERVAL  = uint64(6307200)
	MATURITY_INTERVAL = uint64(3153600)

	SumRewardUntilMaturity = big.NewInt(47304000)
	MaxHalving             = int64(4)

	maxUncles                        = 2
	allowedFutureBlockTimeSeconds    = int64(15)
	allowedFutureBlockTimeSecondsVCT = int64(VCTFutureTolerance)
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
	isVCT := chain.Config().IsVCT(header.Number)
	if !uncle {
		futureAllowance := allowedFutureBlockTimeSeconds
		if isVCT {
			futureAllowance = allowedFutureBlockTimeSecondsVCT
		}
		if header.Time > uint64(unixNow+futureAllowance) {
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
	if isVCT {
		expectThreshold := ecc.CalcEligibilityThreshold(chain, header.Time, parent)
		if header.EligibilityThreshold == nil || header.EligibilityThreshold.Cmp(expectThreshold) != 0 {
			return fmt.Errorf("invalid vct eligibility threshold: have %v, want %v", header.EligibilityThreshold, expectThreshold)
		}
	} else if header.EligibilityThreshold != nil {
		return fmt.Errorf("invalid pre-VCT eligibility threshold: have %v, want nil", header.EligibilityThreshold)
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
		if err := ecc.verifySeal(chain, header); err != nil {
			return err
		}
		if err := ecc.verifyVRFProof(chain, header, parent); err != nil {
			return err
		}
		if isVCT {
			if err := ecc.verifyMiningSig(header, ecc.SealHash(header).Bytes(), isVCT); err != nil {
				return err
			}
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
// Pre-VCT blocks (Seoul phase) carry no VRF proof and are skipped.
// parent must be non-nil; it is used to compute deltaT for progressive timeout verification.
func (ecc *ECC) verifyVRFProof(chain consensus.ChainHeaderReader, header, parent *types.Header) error {
	if !chain.Config().IsVCT(header.Number) {
		// Seoul phase: pure ECCPoW, no eligibility proof required.
		return nil
	}
	if header.EligibilityThreshold == nil || header.EligibilityThreshold.Sign() <= 0 || header.EligibilityThreshold.Cmp(EligibilityThresholdMax) > 0 {
		return fmt.Errorf("VCT: invalid eligibility threshold %v", header.EligibilityThreshold)
	}
	if len(header.VRFProof) == 0 {
		return errors.New("VCT: VRF proof missing")
	}
	if len(header.VRFPublicKey) != 33 {
		return fmt.Errorf("VCT: VRF public key must be 33 bytes, got %d", len(header.VRFPublicKey))
	}

	blockNumber := header.Number.Uint64()

	var rawDeltaT uint64 // elapsed header seconds since parent
	// WIP-6: verify Address(VRFPublicKey) == Coinbase.
	pub, err := crypto.DecompressPubkey(header.VRFPublicKey)
	if err != nil {
		return fmt.Errorf("VCT: failed to decompress VRF public key: %w", err)
	}
	vrfAddr := crypto.PubkeyToAddress(*pub)
	if vrfAddr != header.Coinbase {
		return fmt.Errorf("VCT: VRF public key address %v != coinbase %v", vrfAddr, header.Coinbase)
	}
	// WIP-6: VRF message = VCT_VRF || chainId || phash_{h-1} || h.
	chainIDBytes := ecc.chainIDBytes()
	msg := computeVRFMsg(chainIDBytes, header.ParentHash.Bytes(), blockNumber)

	// Compute elapsed header time for progressive timeout eligibility.
	if header.Time > parent.Time {
		rawDeltaT = header.Time - parent.Time
	}
	deltaT := EffectiveDeltaT(rawDeltaT)

	if _, err := VRFVerify(header.VRFPublicKey, header.VRFProof, msg); err != nil {
		return fmt.Errorf("VCT: VRF proof invalid: %w", err)
	}

	// WIP-6: time-dependent threshold (progressive timeout liveness guarantee).
	if !CheckEligibilityWithBaseAndTime(header.VRFProof, header.EligibilityThreshold, deltaT) {
		return fmt.Errorf("VCT: VRF proof does not pass eligibility threshold (raw deltaT=%d s, effective deltaT=%d s)", rawDeltaT, deltaT)
	}

	log.Debug("VCT: VRF proof verified", "block", blockNumber, "epoch", EligibilityEpoch(blockNumber), "rawDeltaT", rawDeltaT, "effectiveDeltaT", deltaT)
	return nil
}

func (ecc *ECC) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	next := new(big.Int).Add(parent.Number, big1)
	if chain.Config().IsVCT(next) {
		rawDiff := applyVCTMinimumDifficulty(ecc.calcBaseDifficulty(chain, time, parent))
		threshold := ecc.CalcEligibilityThreshold(chain, time, parent)
		if threshold.Cmp(EligibilityBase) > 0 {
			// During bootstrap, spend difficulty-increase pressure on lowering
			// the eligibility threshold first. If the threshold is already maxed
			// out and blocks are still slow, probability cannot be raised further,
			// so difficulty must be allowed to decrease for liveness.
			if threshold.Cmp(EligibilityThresholdMax) >= 0 && rawDiff.Cmp(parent.Difficulty) < 0 {
				return rawDiff
			}
			return applyVCTMinimumDifficulty(parent.Difficulty)
		}
		return rawDiff
	}
	return ecc.calcBaseDifficulty(chain, time, parent)
}

func applyVCTMinimumDifficulty(diff *big.Int) *big.Int {
	if diff.Cmp(VCTMinimumDifficulty) < 0 {
		return new(big.Int).Set(VCTMinimumDifficulty)
	}
	return new(big.Int).Set(diff)
}

func (ecc *ECC) calcBaseDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	next := new(big.Int).Add(parent.Number, big1)
	switch {
	case chain.Config().IsVCT(next):
		return calcDifficultyAnnapurna(chain, time, parent)
	case chain.Config().IsAnnapurna(next):
		return calcDifficultyAnnapurna(chain, time, parent)
	case chain.Config().IsSeoul(next):
		return calcDifficultySeoul(chain, time, parent)
	default:
		return calcDifficultyFrontier(time, parent)
	}
}

// CalcEligibilityThreshold returns the adaptive VCT base eligibility threshold for
// the child block of parent at the given timestamp. During bootstrap it starts
// at 256 (all VRF outputs immediately eligible) and spends the difficulty
// adjustment signal on lowering the threshold down to EligibilityBase before
// allowing ECCPoW difficulty to move again.
func (ecc *ECC) CalcEligibilityThreshold(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	next := new(big.Int).Add(parent.Number, big1)
	if !chain.Config().IsVCT(next) {
		return nil
	}
	if !chain.Config().IsVCT(parent.Number) {
		if cfg := chain.Config().Vct; cfg != nil && cfg.InitialEligibilityThreshold != nil && cfg.InitialEligibilityThreshold.Sign() > 0 {
			return ConfigEligibilityThreshold(cfg.InitialEligibilityThreshold)
		}
		return new(big.Int).Set(EligibilityThresholdMax)
	}
	parentThreshold := cloneThreshold(parent.EligibilityThreshold)

	threshold := new(big.Int).Set(parentThreshold)
	if parentThreshold.Cmp(EligibilityBase) > 0 {
		rawDiff := ecc.calcBaseDifficulty(chain, time, parent)
		if rawDiff.Sign() > 0 && parent.Difficulty.Sign() > 0 {
			num := new(big.Int).Mul(new(big.Int).Set(parentThreshold), parent.Difficulty)
			num.Add(num, new(big.Int).Sub(rawDiff, big1)) // ceil(num/rawDiff)
			num.Div(num, rawDiff)
			threshold = num
		}
	}

	// If the parent itself required the full timeout window, relax the next
	// block's base threshold. This is a conservative liveness response; the
	// normal bootstrap rule will lower it again when blocks arrive quickly.
	if chain.Config().IsVCT(parent.Number) && parent.Number.Sign() > 0 {
		grandParent := chain.GetHeader(parent.ParentHash, parent.Number.Uint64()-1)
		if grandParent != nil && parent.Time > grandParent.Time && EffectiveDeltaT(parent.Time-grandParent.Time) >= TimeoutEnd {
			boosted := new(big.Int).Mul(parentThreshold, big2)
			if boosted.Cmp(EligibilityThresholdMax) > 0 {
				boosted = new(big.Int).Set(EligibilityThresholdMax)
			}
			if threshold.Cmp(boosted) < 0 {
				threshold = boosted
			}
		}
	}

	if threshold.Cmp(EligibilityThresholdMax) > 0 {
		threshold = new(big.Int).Set(EligibilityThresholdMax)
	}
	if threshold.Cmp(EligibilityBase) < 0 {
		threshold = new(big.Int).Set(EligibilityBase)
	}
	return threshold
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

	isVCTBlock := chain != nil && chain.Config().IsVCT(header.Number)
	if chain == nil {
		// Remote sealer path (chain=nil): infer from VRF proof presence.
		isVCTBlock = len(header.VRFProof) > 0
	}
	var sealHash []byte
	if isVCTBlock {
		sealHash = ecc.SealHash(header).Bytes()
	} else {
		sealHash = legacySealHash(header).Bytes()
	}
	var powSeed []byte
	if isVCTBlock {
		powSeed = computePowSeedVCT(sealHash, header.Nonce.Uint64(), header.VRFSignature)
	} else {
		powSeed = computeLegacyPowSeed(sealHash, header.Nonce.Uint64())
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
	if chain.Config().IsVCT(header.Number) {
		header.EligibilityThreshold = ecc.CalcEligibilityThreshold(chain, header.Time, parent)
	} else {
		header.EligibilityThreshold = nil
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
	if chain.Config().IsVCT(header.Number) {
		accumulateRewards(chain.Config(), state, header, uncles)
	} else {
		accumulateRewardsLegacy(chain.Config(), state, header, uncles)
	}
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
	//   Nonce, MixDigest, Codeword - PoW outputs
	//   VRFSignature               - per-nonce mining signature
	//   CodeLength                 - derived from difficulty by mine_seoul and written back
	// VRFPublicKey, VRFProof, and EligibilityThreshold are included because they
	// select and prove the VRF eligibility gate.
	enc := []interface{}{
		header.ParentHash, header.UncleHash, header.Coinbase,
		header.Root, header.TxHash, header.ReceiptHash,
		header.Bloom, header.Difficulty, header.Number,
		header.GasLimit, header.GasUsed, header.Time, header.Extra,
		header.VRFPublicKey, header.VRFProof,
		header.EligibilityThreshold,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	rlp.Encode(hasher, enc)
	hasher.Sum(hash[:0])
	return hash
}

// legacySealHash returns the pre-VCT (Seoul-phase) block seal hash.
// It matches eccpow.SealHash exactly, with no domain prefix, so that pre-fork
// blocks can be cross-validated between old eccpow nodes and this VCT engine.
func legacySealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
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
// signature by the block's coinbase: ECRecover(?_館, m_館) = coinbase.
// WIP-6 (isVCT=true): m_館 = Keccak256(VCT_MINE || sealHash || nonce).
// Pre-WIP-6:          m_館 = Keccak256(VCT_MINE || chainId || sealHash || nonce).
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

// accumulateRewardsLegacy mirrors eccpow's reward logic for pre-VCT (Seoul) blocks.
// 4 WL base reward, no treasury split, with WorldLand halving/maturity schedule.
func accumulateRewardsLegacy(config *params.ChainConfig, state *state.StateDB, header *types.Header, uncles []*types.Header) {
	blockReward := new(big.Int).Set(FrontierBlockReward)
	if config.IsByzantium(header.Number) {
		blockReward = new(big.Int).Set(ByzantiumBlockReward)
	}
	if config.IsConstantinople(header.Number) {
		blockReward = new(big.Int).Set(ConstantinopleBlockReward)
	}
	if config.IsWorldland(header.Number) {
		blockReward = new(big.Int).Set(WorldLandBlockReward)
		if config.IsWorldLandHalving(header.Number) {
			blockHeight := header.Number.Uint64()
			halvingLevel := (blockHeight - 1 - config.WorldlandBlock.Uint64()) / HALVING_INTERVAL
			blockReward.Rsh(blockReward, uint(halvingLevel))
		} else if config.IsWorldLandMaturity(header.Number) {
			blockHeight := header.Number.Uint64()
			blockReward = big.NewInt(1e+18)
			maturityLevel := (blockHeight - 1 - config.HalvingEndTime.Uint64()) / MATURITY_INTERVAL
			blockReward.Mul(blockReward, SumRewardUntilMaturity)
			blockReward.Div(blockReward, new(big.Int).SetUint64(MATURITY_INTERVAL))
			blockReward.Mul(blockReward, big.NewInt(4))
			blockReward.Div(blockReward, big.NewInt(100))
			for i := uint64(0); i < maturityLevel; i++ {
				blockReward.Mul(blockReward, big.NewInt(104))
				blockReward.Div(blockReward, big.NewInt(100))
			}
		}
	}
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
	state.AddBalance(header.Coinbase, reward)
}

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
