//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/common/hexutil"
	"github.com/cryptoecc/WorldLand/consensus"
	"github.com/cryptoecc/WorldLand/core/state"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/log"
)

// stateBackend is satisfied by *core.BlockChain; it lets the sealer perform
// the S0 balance check before committing ECCPoW work.
type stateBackend interface {
	StateAt(root common.Hash) (*state.StateDB, error)
}

const staleThreshold = 7

var (
	errNoMiningWork      = errors.New("no mining work available yet")
	errInvalidSealResult = errors.New("invalid or stale proof-of-work solution")
)

// Seal implements consensus.Engine.
// It checks secp256k1 VCT eligibility before mining.
func (ecc *ECC) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	if ecc.config.PowMode == ModeFake || ecc.config.PowMode == ModeFullFake {
		header := block.Header()
		header.Nonce, header.MixDigest = types.BlockNonce{}, common.Hash{}
		select {
		case results <- block.WithSeal(header):
		default:
			log.Warn("VCT: sealing result not read", "mode", "fake", "sealhash", ecc.SealHash(block.Header()))
		}
		return nil
	}
	if ecc.shared != nil {
		return ecc.shared.Seal(chain, block, results, stop)
	}

	blockNumber := block.Header().Number.Uint64()
	header := block.Header()
	isVCT := chain.Config().IsVCT(header.Number)
	isTPMGated := chain.Config().IsTPMGated(header.Number)

	if isVCT {
		coinbase := header.Coinbase
		if err := ecc.EnsureVRFKeys(coinbase); err != nil {
			return fmt.Errorf("VCT: VRF key error: %w", err)
		}

		// TPM-gated blocks grant exactly one VRF trial to an active registered
		// TPM-bound identity. Legacy VCT blocks retain the balance-derived virtual trial rule.
		// blockchain.go enforces the same rule on insertion.
		trialWeight := new(big.Int).Set(big1)
		if !isTPMGated {
			vctCfg := chain.Config().Vct
			if vctCfg == nil {
				return errors.New("VCT: missing VCT configuration")
			}
			if b0 := vctCfg.MinEligibleBalanceAt(header.Number); b0.Sign() > 0 {
				sb, ok := chain.(stateBackend)
				if !ok {
					return fmt.Errorf("VCT: parent-state backend unavailable for balance-weighted eligibility at block %d", blockNumber)
				}
				ph := chain.GetHeaderByHash(header.ParentHash)
				if ph == nil {
					return fmt.Errorf("VCT: parent header unavailable for balance-weighted eligibility at block %d", blockNumber)
				}
				pstate, serr := sb.StateAt(ph.Root)
				if serr != nil {
					return fmt.Errorf("VCT: parent state unavailable for balance-weighted eligibility at block %d: %w", blockNumber, serr)
				}
				bal := pstate.GetBalance(coinbase)
				trialWeight.Div(new(big.Int).Set(bal), b0)
				if trialWeight.Sign() == 0 {
					return fmt.Errorf("VCT: coinbase %s balance %s wei grants zero virtual trials at B0 %s wei, not mining block %d",
						coinbase.Hex(), bal.String(), b0.String(), blockNumber)
				}
			}
		}
		if isTPMGated {
			did, signer, err := ecc.ensureTPMWorkSigner()
			if err != nil {
				return err
			}
			header.TPMDID = append([]byte(nil), did[:]...)
			header.TPMWorkPublicKey = signer.PublicKey()
			header.VRFSignature = nil
		}

		if parentHeader := chain.GetHeaderByHash(header.ParentHash); parentHeader != nil {
			header.EligibilityThreshold = ecc.CalcEligibilityThreshold(chain, header.Time, parentHeader)
			header.Difficulty = ecc.CalcDifficulty(chain, header.Time, parentHeader)
		}

		// VCT phase (Rokis+): VRF eligibility gates who may propose each block.
		_, proof, err := ecc.IsEligibleForBlock(chain, blockNumber, block.Header().ParentHash, header.EligibilityThreshold)
		if err != nil {
			return fmt.Errorf("VCT: eligibility check failed: %w", err)
		}
		output, err := VRFOutputFromProof(proof)
		if err != nil {
			return fmt.Errorf("VCT: cannot extract VRF output: %w", err)
		}
		eligible := EligibilityPassesWithWeight(output, header.EligibilityThreshold, 0, trialWeight)

		if !eligible {
			// WIP-6 progressive timeout: wait until deltaT expands the threshold enough.
			delay := EligibilitySubmitDelayWithWeight(output, header.EligibilityThreshold, trialWeight)

			parentHeader := chain.GetHeaderByHash(header.ParentHash)
			var parentTime uint64
			if parentHeader != nil {
				parentTime = parentHeader.Time
			}
			submitAt := parentTime + delay + VCTFutureTolerance
			log.Info("VCT: not immediately eligible; waiting for progressive timeout",
				"block", blockNumber, "virtualTrials", trialWeight, "delay_s", delay, "submitAt", submitAt)

			deadline := time.Unix(int64(submitAt), 0)
			if waitDur := time.Until(deadline); waitDur > 0 {
				timer := time.NewTimer(waitDur)
				select {
				case <-timer.C:
				case <-stop:
					timer.Stop()
					log.Info("VCT: mining aborted during timeout wait", "block", blockNumber)
					return nil
				}
				timer.Stop()
			}

			nowSec := uint64(time.Now().Unix())
			if nowSec > submitAt {
				header.Time = nowSec
			} else {
				header.Time = submitAt
			}
			if parentHeader := chain.GetHeaderByHash(header.ParentHash); parentHeader != nil {
				header.EligibilityThreshold = ecc.CalcEligibilityThreshold(chain, header.Time, parentHeader)
				header.Difficulty = ecc.CalcDifficulty(chain, header.Time, parentHeader)
			}
			log.Info("VCT: progressive timeout elapsed, proceeding with mining",
				"block", blockNumber, "timestamp", header.Time, "difficulty", header.Difficulty, "threshold", header.EligibilityThreshold)
		} else {
			log.Info("VCT: eligible to mine", "block", blockNumber, "virtualTrials", trialWeight, "threshold", header.EligibilityThreshold)
		}

		// Embed VRF proof + public key in the header.
		header.VRFProof = proof
		ecc.lock.Lock()
		header.VRFPublicKey = make([]byte, len(ecc.vrfPubKey))
		copy(header.VRFPublicKey, ecc.vrfPubKey)
		ecc.lock.Unlock()
	} else {
		// Pre-VCT (Seoul) phase: pure ECCPoW, no eligibility gate.
		// VRFProof and VRFPublicKey are intentionally left empty.
		header.EligibilityThreshold = nil
		log.Debug("VCT: pre-VCT block, skipping eligibility", "block", blockNumber)
	}

	block = block.WithSeal(header)

	abort := make(chan struct{})

	ecc.lock.Lock()
	threads := ecc.threads
	if ecc.rand == nil {
		seed, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
		if err != nil {
			ecc.lock.Unlock()
			return err
		}
		ecc.rand = rand.New(rand.NewSource(seed.Int64()))
	}
	ecc.lock.Unlock()

	if threads == 0 {
		threads = runtime.NumCPU()
	}
	if threads < 0 {
		threads = 0
	}
	if ecc.remote != nil {
		ecc.remote.workCh <- &sealTask{block: block, results: results}
	}

	var (
		pend   sync.WaitGroup
		locals = make(chan *types.Block)
	)
	for i := 0; i < threads; i++ {
		pend.Add(1)
		go func(id int, nonce uint64) {
			defer pend.Done()
			if chain.Config().IsSeoul(block.Header().Number) {
				ecc.mine_seoul(block, id, nonce, abort, locals, isVCT, isTPMGated)
			} else {
				ecc.mine(block, id, nonce, abort, locals, isVCT, isTPMGated)
			}
		}(i, uint64(ecc.rand.Int63()))
	}

	go func() {
		var result *types.Block
		select {
		case <-stop:
			close(abort)
		case result = <-locals:
			select {
			case results <- result:
			default:
				ecc.config.Log.Warn("VCT: sealing result not read", "mode", "local", "sealhash", ecc.SealHash(block.Header()))
			}
			close(abort)
		case <-ecc.update:
			close(abort)
			if err := ecc.Seal(chain, block, results, stop); err != nil {
				ecc.config.Log.Error("VCT: failed to restart sealing", "err", err)
			}
		}
		pend.Wait()
	}()
	return nil
}

func (ecc *ECC) mine(block *types.Block, id int, seed uint64, abort chan struct{}, found chan *types.Block, isVCT, isTPMGated bool) {
	header := block.Header()
	var sealHash []byte
	if isVCT {
		sealHash = ecc.SealHash(header).Bytes()
	} else {
		sealHash = legacySealHash(header).Bytes()
	}

	var prv *ecdsa.PrivateKey
	var vrfOutput [32]byte
	var workDID common.Hash
	var workSigner interface {
		SignDigest([]byte) ([]byte, error)
	}
	if isVCT {
		if isTPMGated {
			var err error
			workDID, workSigner, err = ecc.ensureTPMWorkSigner()
			if err != nil {
				log.Error("VCT: mine: TPM work signer unavailable", "err", err)
				return
			}
		} else {
			ecc.lock.Lock()
			seckey := append([]byte(nil), ecc.vrfSecKey...)
			ecc.lock.Unlock()
			var err error
			prv, err = crypto.ToECDSA(seckey)
			if err != nil {
				log.Error("VCT: mine: invalid VRF key", "err", err)
				return
			}
		}

		var err error
		vrfOutput, err = VRFOutputFromProof(header.VRFProof)
		if err != nil {
			log.Error("VCT: mine: cannot derive VRF output", "err", err)
			return
		}
	}

	parameters, _ := setParameters(header)
	H := generateH(parameters)
	colInRow, rowInCol := generateQ(parameters, H)

	var (
		attempts int64
		nonce    = seed
	)
	logger := log.New("miner", id)
	logger.Trace("VCT: started nonce search", "seed", seed)

search:
	for {
		select {
		case <-abort:
			logger.Trace("VCT: nonce search aborted", "attempts", nonce-seed)
			ecc.hashrate.Mark(attempts)
			break search
		default:
			attempts++
			if attempts%(1<<15) == 0 {
				ecc.hashrate.Mark(attempts)
				attempts = 0
			}

			var (
				digest []byte
				sigma  []byte
			)
			if isTPMGated {
				workMessage := computeTPMWorkSigMsg(ecc.chainIDBytes(), sealHash, workDID, vrfOutput, nonce)
				var serr error
				sigma, serr = workSigner.SignDigest(workMessage)
				if serr != nil {
					logger.Warn("VCT: TPM work authorization failed", "err", serr)
					nonce++
					continue
				}
				digest = crypto.Keccak512(computeTPMPowSeed(workMessage, sigma))
			} else if isVCT {
				var serr error
				sigma, serr = crypto.Sign(computeMiningSigMsgVCT(sealHash, vrfOutput, nonce), prv)
				if serr != nil {
					logger.Warn("VCT: mining authorization sign failed", "err", serr)
					nonce++
					continue
				}
				powSeed := computePowSeedVCT(sealHash, vrfOutput, nonce, sigma)
				digest = crypto.Keccak512(powSeed)
			} else {
				powSeed := computeLegacyPowSeed(sealHash, nonce)
				digest = crypto.Keccak512(powSeed)
			}

			hv := generateHv(parameters, digest)
			hv, ow, _ := OptimizedDecoding(parameters, hv, H, rowInCol, colInRow)
			if ok, _ := MakeDecision(header, colInRow, ow); ok {
				header = types.CopyHeader(header)
				header.MixDigest = common.BytesToHash(digest)
				header.Nonce = types.EncodeNonce(nonce)
				header.Codeword = packCodeword(ow)
				if isTPMGated {
					header.TPMWorkSignature = sigma
				} else if isVCT {
					header.VRFSignature = sigma
				}
				select {
				case found <- block.WithSeal(header):
				case <-abort:
				}
				break search
			}
			nonce++
		}
	}
}

func (ecc *ECC) mine_seoul(block *types.Block, id int, seed uint64, abort chan struct{}, found chan *types.Block, isVCT, isTPMGated bool) {
	header := block.Header()
	var sealHash []byte
	if isVCT {
		sealHash = ecc.SealHash(header).Bytes()
	} else {
		sealHash = legacySealHash(header).Bytes()
	}

	var prv *ecdsa.PrivateKey
	var vrfOutput [32]byte
	var workDID common.Hash
	var workSigner interface {
		SignDigest([]byte) ([]byte, error)
	}
	if isVCT {
		if isTPMGated {
			var err error
			workDID, workSigner, err = ecc.ensureTPMWorkSigner()
			if err != nil {
				log.Error("VCT: mine_seoul: TPM work signer unavailable", "err", err)
				return
			}
		} else {
			ecc.lock.Lock()
			seckey := append([]byte(nil), ecc.vrfSecKey...)
			ecc.lock.Unlock()
			var err error
			prv, err = crypto.ToECDSA(seckey)
			if err != nil {
				log.Error("VCT: mine_seoul: invalid VRF key", "err", err)
				return
			}
		}

		var err error
		vrfOutput, err = VRFOutputFromProof(header.VRFProof)
		if err != nil {
			log.Error("VCT: mine_seoul: cannot derive VRF output", "err", err)
			return
		}
	}

	parameters, _ := setParameters_Seoul(header)
	H := generateH(parameters)
	colInRow, rowInCol := generateQ(parameters, H)

	var (
		attempts int64
		nonce    = seed
	)
	logger := log.New("miner", id)
	logger.Trace("VCT: started Seoul nonce search", "seed", seed)

search:
	for {
		select {
		case <-abort:
			logger.Trace("VCT: nonce search aborted", "attempts", nonce-seed)
			ecc.hashrate.Mark(attempts)
			break search
		default:
			attempts++
			if attempts%(1<<15) == 0 {
				ecc.hashrate.Mark(attempts)
				attempts = 0
			}

			var (
				digest []byte
				sigma  []byte
			)
			if isTPMGated {
				workMessage := computeTPMWorkSigMsg(ecc.chainIDBytes(), sealHash, workDID, vrfOutput, nonce)
				var serr error
				sigma, serr = workSigner.SignDigest(workMessage)
				if serr != nil {
					logger.Warn("VCT: TPM work authorization failed", "err", serr)
					nonce++
					continue
				}
				digest = crypto.Keccak512(computeTPMPowSeed(workMessage, sigma))
			} else if isVCT {
				var serr error
				sigma, serr = crypto.Sign(computeMiningSigMsgVCT(sealHash, vrfOutput, nonce), prv)
				if serr != nil {
					logger.Warn("VCT: mining authorization sign failed", "err", serr)
					nonce++
					continue
				}
				powSeed := computePowSeedVCT(sealHash, vrfOutput, nonce, sigma)
				digest = crypto.Keccak512(powSeed)
			} else {
				powSeed := computeLegacyPowSeed(sealHash, nonce)
				digest = crypto.Keccak512(powSeed)
			}

			hv := generateHv(parameters, digest)
			hv, ow, _ := OptimizedDecodingSeoul(parameters, hv, H, rowInCol, colInRow)
			if ok, _ := MakeDecision_Seoul(header, colInRow, ow); ok {
				header = types.CopyHeader(header)
				header.CodeLength = uint64(parameters.n)
				header.MixDigest = common.BytesToHash(digest)
				header.Nonce = types.EncodeNonce(nonce)
				header.Codeword = packCodeword(ow)
				if isTPMGated {
					header.TPMWorkSignature = sigma
				} else if isVCT {
					header.VRFSignature = sigma
				}
				select {
				case found <- block.WithSeal(header):
				case <-abort:
				}
				break search
			}
			nonce++
		}
	}
}

func packCodeword(outputWord []int) []byte {
	var codeword []byte
	var codeVal byte
	for i, v := range outputWord {
		codeVal |= byte(v) << (7 - i%8)
		if i%8 == 7 {
			codeword = append(codeword, codeVal)
			codeVal = 0
		}
	}
	if len(outputWord)%8 != 0 {
		codeword = append(codeword, codeVal)
	}
	return codeword
}

// -- Remote sealer -------------------------------------------------------------

const remoteSealerTimeout = 1 * time.Second

type remoteSealer struct {
	works        map[common.Hash]*types.Block
	rates        map[common.Hash]hashrate
	currentBlock *types.Block
	currentWork  [4]string
	notifyCtx    context.Context
	cancelNotify context.CancelFunc
	reqWG        sync.WaitGroup

	ecc          *ECC
	noverify     bool
	notifyURLs   []string
	results      chan<- *types.Block
	workCh       chan *sealTask
	fetchWorkCh  chan *sealWork
	submitWorkCh chan *mineResult
	fetchRateCh  chan chan uint64
	submitRateCh chan *hashrate
	requestExit  chan struct{}
	exitCh       chan struct{}
}

type sealTask struct {
	block   *types.Block
	results chan<- *types.Block
}

type mineResult struct {
	nonce     types.BlockNonce
	mixDigest common.Hash
	hash      common.Hash
	errc      chan error
}

type hashrate struct {
	id   common.Hash
	ping time.Time
	rate uint64
	done chan struct{}
}

type sealWork struct {
	errc chan error
	res  chan [4]string
}

func startRemoteSealer(ecc *ECC, urls []string, noverify bool) *remoteSealer {
	ctx, cancel := context.WithCancel(context.Background())
	s := &remoteSealer{
		ecc:          ecc,
		noverify:     noverify,
		notifyURLs:   urls,
		notifyCtx:    ctx,
		cancelNotify: cancel,
		works:        make(map[common.Hash]*types.Block),
		rates:        make(map[common.Hash]hashrate),
		workCh:       make(chan *sealTask),
		fetchWorkCh:  make(chan *sealWork),
		submitWorkCh: make(chan *mineResult),
		fetchRateCh:  make(chan chan uint64),
		submitRateCh: make(chan *hashrate),
		requestExit:  make(chan struct{}),
		exitCh:       make(chan struct{}),
	}
	go s.loop()
	return s
}

func (s *remoteSealer) loop() {
	defer func() {
		s.ecc.config.Log.Trace("VCT: remote sealer exiting")
		s.cancelNotify()
		s.reqWG.Wait()
		close(s.exitCh)
	}()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case work := <-s.workCh:
			s.results = work.results
			s.makeWork(work.block)
			s.notifyWork()
		case work := <-s.fetchWorkCh:
			if s.currentBlock == nil {
				work.errc <- errNoMiningWork
			} else {
				work.res <- s.currentWork
			}
		case result := <-s.submitWorkCh:
			if s.submitWork(result.nonce, result.mixDigest, result.hash) {
				result.errc <- nil
			} else {
				result.errc <- errInvalidSealResult
			}
		case result := <-s.submitRateCh:
			s.rates[result.id] = hashrate{rate: result.rate, ping: time.Now()}
			close(result.done)
		case req := <-s.fetchRateCh:
			var total uint64
			for _, rate := range s.rates {
				total += rate.rate
			}
			req <- total
		case <-ticker.C:
			for id, rate := range s.rates {
				if time.Since(rate.ping) > 10*time.Second {
					delete(s.rates, id)
				}
			}
			if s.currentBlock != nil {
				for hash, block := range s.works {
					if block.NumberU64()+staleThreshold <= s.currentBlock.NumberU64() {
						delete(s.works, hash)
					}
				}
			}
		case <-s.requestExit:
			return
		}
	}
}

func (s *remoteSealer) makeWork(block *types.Block) {
	header := block.Header()
	hash := s.ecc.SealHash(header)
	if len(header.VRFProof) == 0 {
		hash = legacySealHash(header)
	}
	s.currentWork[0] = hash.Hex()
	s.currentWork[1] = common.BytesToHash(SeedHash(block.NumberU64())).Hex()
	s.currentWork[2] = common.BytesToHash(new(big.Int).Div(two256, block.Difficulty()).Bytes()).Hex()
	s.currentWork[3] = hexutil.EncodeBig(block.Number())
	s.currentBlock = block
	s.works[hash] = block
}

func (s *remoteSealer) notifyWork() {
	work := s.currentWork
	var blob []byte
	if s.ecc.config.NotifyFull {
		blob, _ = json.Marshal(s.currentBlock.Header())
	} else {
		blob, _ = json.Marshal(work)
	}
	s.reqWG.Add(len(s.notifyURLs))
	for _, url := range s.notifyURLs {
		go s.sendNotification(s.notifyCtx, url, blob, work)
	}
}

func (s *remoteSealer) sendNotification(ctx context.Context, url string, jsonBlob []byte, work [4]string) {
	defer s.reqWG.Done()
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBlob))
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, remoteSealerTimeout)
	defer cancel()
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

func (s *remoteSealer) submitWork(nonce types.BlockNonce, mixDigest common.Hash, sealhash common.Hash) bool {
	if s.currentBlock == nil {
		return false
	}
	block := s.works[sealhash]
	if block == nil {
		return false
	}
	header := block.Header()
	header.Nonce = nonce
	header.MixDigest = mixDigest

	start := time.Now()
	if !s.noverify {
		if err := s.ecc.verifySeal(nil, header); err != nil {
			s.ecc.config.Log.Warn("VCT: invalid PoW submitted", "sealhash", sealhash, "elapsed", common.PrettyDuration(time.Since(start)), "err", err)
			return false
		}
	}
	if s.results == nil {
		return false
	}
	solution := block.WithSeal(header)
	if solution.NumberU64()+staleThreshold > s.currentBlock.NumberU64() {
		select {
		case s.results <- solution:
			return true
		default:
			return false
		}
	}
	return false
}
