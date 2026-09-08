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
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
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
	if err := ecc.bindChainContext(chain); err != nil {
		return err
	}
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
	if err := ecc.bindChainContext(chain); err != nil {
		abort, results := make(chan struct{}), make(chan error, len(headers))
		for range headers {
			results <- err
		}
		return abort, results
	}
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
	batchIndex := batchHeaderIndex(headers)
	for i := 0; i < workers; i++ {
		go func() {
			for index := range inputs {
				context := &batchHeaderReader{ChainHeaderReader: chain, headers: batchIndex, limit: index}
				errs[index] = ecc.verifyHeaderWorker(context, headers, seals, index, unixNow)
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
		if err := ecc.verifyUncleProposerEligibility(chain, uncle, ancestors[uncle.ParentHash]); err != nil {
			return err
		}
	}
	return nil
}

// verifyUncleProposerEligibility applies VCT's state-dependent S0 gate to an
// uncle using the state committed by that uncle's own parent. Pre-VCT uncles
// retain legacy behavior and do not require historical state access.
func (ecc *ECC) verifyUncleProposerEligibility(chain consensus.ChainReader, uncle, parent *types.Header) error {
	if !chain.Config().IsVCT(uncle.Number) {
		return nil
	}
	stateChain, ok := chain.(consensus.ChainStateReader)
	if !ok {
		return errors.New("VCT: chain state reader required for uncle proposer eligibility")
	}
	parentState, err := stateChain.StateAt(parent.Root)
	if err != nil {
		return fmt.Errorf("VCT: uncle parent state unavailable: %w", err)
	}
	if parentState == nil {
		return errors.New("VCT: uncle parent state unavailable")
	}
	if err := ecc.VerifyProposerEligibility(chain, uncle, parent, parentState); err != nil {
		return fmt.Errorf("VCT: invalid uncle proposer: %w", err)
	}
	return nil
}

// verifyPreVCTFields rejects even explicitly empty VCT extension fields. Their
// mere presence changes the full header hash while the legacy seal hash does
// not commit to them, so all four fields must be absent before VCTBlock.
func verifyPreVCTFields(header *types.Header) error {
	if header.VRFPublicKey != nil || header.VRFProof != nil || header.VRFSignature != nil || header.EligibilityThreshold != nil ||
		header.TPMDID != nil || header.TPMWorkPublicKey != nil || header.TPMWorkSignature != nil {
		return errors.New("invalid pre-VCT header: VCT extension fields must be absent")
	}
	return nil
}

func verifyTPMFieldEra(header *types.Header, active bool) error {
	if !active {
		// RLP must encode empty placeholders for these optional byte fields when
		// the later EligibilityThreshold field is present. Decode therefore
		// normalizes nil to a non-nil, zero-length slice on the wire.
		if len(header.TPMDID) != 0 || len(header.TPMWorkPublicKey) != 0 || len(header.TPMWorkSignature) != 0 {
			return errors.New("VCT: TPM work fields present before TPM-gated fork")
		}
		return nil
	}
	if len(header.TPMDID) != common.HashLength {
		return fmt.Errorf("VCT: TPM identity must be %d bytes, got %d", common.HashLength, len(header.TPMDID))
	}
	if len(header.TPMWorkPublicKey) != tpmwork.PublicKeySize {
		return fmt.Errorf("VCT: TPM work public key must be %d bytes, got %d", tpmwork.PublicKeySize, len(header.TPMWorkPublicKey))
	}
	if len(header.TPMWorkSignature) != tpmwork.SignatureSize {
		return fmt.Errorf("VCT: TPM work signature must be %d bytes, got %d", tpmwork.SignatureSize, len(header.TPMWorkSignature))
	}
	// TPM fields follow VRFSignature in the RLP layout, so a TPM-gated header
	// carries an empty placeholder that decodes as []byte{}, not nil.
	if len(header.VRFSignature) != 0 {
		return errors.New("VCT: legacy mining signature present after TPM-gated fork")
	}
	return nil
}

func (ecc *ECC) verifyHeader(chain consensus.ChainHeaderReader, header, parent *types.Header, uncle bool, seal bool, unixNow int64) error {
	if err := ecc.bindChainContext(chain); err != nil {
		return err
	}
	if uint64(len(header.Extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("extra-data too long: %d > %d", len(header.Extra), params.MaximumExtraDataSize)
	}
	isVCT := chain.Config().IsVCT(header.Number)
	isTPMGated := chain.Config().IsTPMGated(header.Number)
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
	} else if err := verifyPreVCTFields(header); err != nil {
		return err
	}
	if isVCT {
		if err := verifyTPMFieldEra(header, isTPMGated); err != nil {
			return err
		}
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
		if err := ecc.verifyVRFProof(chain, header, parent); err != nil {
			return err
		}
		if err := ecc.verifySeal(chain, header); err != nil {
			return err
		}
		if isTPMGated {
			if err := ecc.verifyTPMWorkSig(chain, header, ecc.SealHash(header).Bytes()); err != nil {
				return err
			}
		} else if isVCT {
			if err := ecc.verifyMiningSig(chain, header, ecc.SealHash(header).Bytes(), isVCT); err != nil {
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
	// WIP-6: bind the VRF input to the configured branch-local delayed seed.
	msg, err := ecc.delayedVRFMessage(chain, parent, blockNumber)
	if err != nil {
		return err
	}

	// Compute elapsed header time for progressive timeout eligibility.
	if header.Time > parent.Time {
		rawDeltaT = header.Time - parent.Time
	}
	deltaT := EffectiveDeltaT(rawDeltaT)

	output, err := VRFVerify(header.VRFPublicKey, header.VRFProof, msg)
	if err != nil {
		return fmt.Errorf("VCT: VRF proof invalid: %w", err)
	}

	// Eligibility itself is checked by VerifyProposerEligibility, which has
	// access to the parent state and can derive the balance trial weight.
	_ = output
	log.Debug("VCT: VRF proof verified; balance threshold deferred to stateful verification", "block", blockNumber, "rawDeltaT", rawDeltaT, "effectiveDeltaT", deltaT)
	return nil
}

func (ecc *ECC) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	next := new(big.Int).Add(parent.Number, big1)
	if chain.Config().IsVCT(next) {
		rawDiff := applyVCTMinimumDifficulty(ecc.calcBaseDifficulty(chain, time, parent))
		threshold := ecc.CalcEligibilityThreshold(chain, time, parent)
		if threshold.Cmp(EligibilityBase) > 0 {
			// While admission has slack, spend the Annapurna timing signal on
			// eligibility and keep difficulty fixed. At full eligibility, a
			// remaining slow-block signal must lower difficulty for liveness.
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
// allowing ECCPoW difficulty to move again. EligibilityBase is a lower bound,
// not a set point that relaxed operation must return to after a permanent hash
// power change.
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
	// block's base threshold. The same sensitivity-driven rule lowers it again
	// only when subsequent blocks are faster than the controller target.
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
	if chain != nil {
		if err := ecc.bindChainContext(chain); err != nil {
			return err
		}
	}
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

	isVCTBlock := chain != nil && chain.Config().IsVCT(header.Number)
	isTPMGatedBlock := chain != nil && chain.Config().IsTPMGated(header.Number)
	if chain == nil {
		// Remote sealer path (chain=nil): infer from VRF proof presence.
		isVCTBlock = len(header.VRFProof) > 0
		isTPMGatedBlock = len(header.TPMDID) > 0
	}
	var sealHash []byte
	if isVCTBlock {
		sealHash = ecc.SealHash(header).Bytes()
	} else {
		sealHash = legacySealHash(header).Bytes()
	}
	var powSeed []byte
	if isVCTBlock {
		vrfOutput, err := ecc.verifiedVRFOutput(chain, header)
		if err != nil {
			return fmt.Errorf("VCT: cannot derive verified VRF output for PoW seed: %w", err)
		}
		if isTPMGatedBlock {
			workMessage := computeTPMWorkSigMsg(ecc.chainIDBytes(), sealHash, common.BytesToHash(header.TPMDID), vrfOutput, header.Nonce.Uint64())
			powSeed = computeTPMPowSeed(workMessage, header.TPMWorkSignature)
		} else {
			powSeed = computePowSeedVCT(sealHash, vrfOutput, header.Nonce.Uint64(), header.VRFSignature)
		}
	} else {
		powSeed = computeLegacyPowSeed(sealHash, header.Nonce.Uint64())
	}

	var (
		digest []byte
		flag   bool
	)
	if chain == nil || chain.Config().IsSeoul(header.Number) {
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
	if err := ecc.bindChainContext(chain); err != nil {
		return err
	}
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
	//   VRFSignature, TPMWorkSignature - per-trial mining authorization signatures
	//   CodeLength                 - derived from difficulty by mine_seoul and written back
	// VRFPublicKey and EligibilityThreshold are included because they select the
	// eligibility gate. VRFProof is deliberately excluded: valid proofs may be
	// malleable, while computePowSeedVCT separately commits to the unique,
	// verified VRF output.
	enc := []interface{}{
		header.ParentHash, header.UncleHash, header.Coinbase,
		header.Root, header.TxHash, header.ReceiptHash,
		header.Bloom, header.Difficulty, header.Number,
		header.GasLimit, header.GasUsed, header.Time, header.Extra,
		header.VRFPublicKey,
		header.EligibilityThreshold,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	// Preserve the exact pre-TPM VCT seal hash when both fields are absent.
	// TPM headers append the legacy-named identity and work key after the legacy field sequence.
	if header.TPMDID != nil || header.TPMWorkPublicKey != nil {
		enc = append(enc, header.TPMDID, header.TPMWorkPublicKey)
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

// verifyMiningSig checks that header.VRFSignature is a valid per-trial mining
// signature by the block's coinbase account.
// WIP-6:     m = Keccak256(VCT_MINE || sealHash || verifiedVRFOutput || nonce).
// Pre-WIP-6: m = Keccak256(VCT_MINE || chainId || sealHash || nonce).
func (ecc *ECC) verifyMiningSig(chain consensus.ChainHeaderReader, header *types.Header, sealHash []byte, isVCT bool) error {
	if len(header.VRFSignature) != 65 {
		return fmt.Errorf("VCT: VRFSignature must be 65 bytes, got %d", len(header.VRFSignature))
	}
	r := new(big.Int).SetBytes(header.VRFSignature[:32])
	s := new(big.Int).SetBytes(header.VRFSignature[32:64])
	v := header.VRFSignature[64]
	if !crypto.ValidateSignatureValues(v, r, s, true) {
		return errors.New("VCT: mining signature is not canonical low-s ECDSA")
	}
	var msgHash []byte
	if isVCT {
		vrfOutput, err := ecc.verifiedVRFOutput(chain, header)
		if err != nil {
			return fmt.Errorf("VCT: cannot derive verified VRF output for mining signature: %w", err)
		}
		msgHash = computeMiningSigMsgVCT(sealHash, vrfOutput, header.Nonce.Uint64())
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

// verifyTPMWorkSig authenticates one nonce trial with the P-256 work key in
// the header. Stateful proposer verification separately binds that key to the
// active TPM-bound identity registration in the parent state.
func (ecc *ECC) verifyTPMWorkSig(chain consensus.ChainHeaderReader, header *types.Header, sealHash []byte) error {
	if len(header.TPMDID) != common.HashLength {
		return fmt.Errorf("VCT: TPM identity must be %d bytes, got %d", common.HashLength, len(header.TPMDID))
	}
	vrfOutput, err := ecc.verifiedVRFOutput(chain, header)
	if err != nil {
		return fmt.Errorf("VCT: cannot derive verified VRF output for TPM work signature: %w", err)
	}
	workMessage := computeTPMWorkSigMsg(ecc.chainIDBytes(), sealHash, common.BytesToHash(header.TPMDID), vrfOutput, header.Nonce.Uint64())
	if !tpmwork.VerifyDigest(header.TPMWorkPublicKey, workMessage, header.TPMWorkSignature) {
		return errors.New("VCT: invalid TPM work signature")
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
