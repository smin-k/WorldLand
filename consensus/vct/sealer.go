//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"bytes"
	"context"
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
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/log"
)

const staleThreshold = 7

var (
	errNoMiningWork      = errors.New("no mining work available yet")
	errInvalidSealResult = errors.New("invalid or stale proof-of-work solution")
)

// Seal implements consensus.Engine.
// It checks secp256k1 VRF sortition eligibility before mining.
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

	coinbase := block.Header().Coinbase
	if err := ecc.EnsureVRFKeys(coinbase); err != nil {
		return fmt.Errorf("VCT: VRF key error: %w", err)
	}

	blockNumber := block.Header().Number.Uint64()
	eligible, proof, err := ecc.IsEligibleForBlock(chain, blockNumber, block.Header().ParentHash)
	if err != nil {
		return fmt.Errorf("VCT: sortition check failed: %w", err)
	}

	// Copy header early; we may need to update Time and Difficulty for the timeout case.
	header := block.Header()

	if !eligible {
		if !chain.Config().IsVCT(header.Number) {
			// Pre-VCT: reject immediately (legacy behaviour).
			log.Info("VCT: not eligible for this epoch", "block", blockNumber, "epoch", SortitionEpoch(blockNumber))
			return errors.New("VCT: not eligible for sortition epoch")
		}

		// WIP-6 progressive timeout: wait until this miner's VRF output falls
		// below the time-expanded threshold, then mine with the updated timestamp.
		output, oerr := VRFOutputFromProof(proof)
		if oerr != nil {
			return fmt.Errorf("VCT: cannot extract VRF output: %w", oerr)
		}
		delay := SortitionSubmitDelay(output[0])

		parentHeader := chain.GetHeaderByHash(header.ParentHash)
		var parentTime uint64
		if parentHeader != nil {
			parentTime = parentHeader.Time
		}
		submitAt := parentTime + delay
		log.Info("VCT: not immediately eligible — waiting for progressive timeout",
			"block", blockNumber, "delay_s", delay, "submitAt", submitAt)

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

		// Set block timestamp to max(submitAt, now()) so the verifier sees
		// Δt ≥ delay and accepts the block.
		nowSec := uint64(time.Now().Unix())
		if nowSec > submitAt {
			header.Time = nowSec
		} else {
			header.Time = submitAt
		}
		// Recalculate difficulty for the updated timestamp (sealHash commits to Difficulty).
		if parentHeader != nil {
			header.Difficulty = ecc.CalcDifficulty(chain, header.Time, parentHeader)
		}
		log.Info("VCT: progressive timeout elapsed, proceeding with mining",
			"block", blockNumber, "timestamp", header.Time, "difficulty", header.Difficulty)
	} else {
		log.Info("VCT: eligible to mine", "block", blockNumber, "epoch", SortitionEpoch(blockNumber))
	}

	// Embed VRF proof + public key in the header (which may have updated Time/Difficulty).
	header.VRFProof = proof
	ecc.lock.Lock()
	header.VRFPublicKey = make([]byte, len(ecc.vrfPubKey))
	copy(header.VRFPublicKey, ecc.vrfPubKey)
	ecc.lock.Unlock()
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
	isVCT := chain.Config().IsVCT(block.Header().Number)
	for i := 0; i < threads; i++ {
		pend.Add(1)
		go func(id int, nonce uint64) {
			defer pend.Done()
			if chain.Config().IsSeoul(block.Header().Number) {
				ecc.mine_seoul(block, id, nonce, abort, locals, isVCT)
			} else {
				ecc.mine(block, id, nonce, abort, locals, isVCT)
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

func (ecc *ECC) mine(block *types.Block, id int, seed uint64, abort chan struct{}, found chan *types.Block, isVCT bool) {
	ecc.lock.Lock()
	seckey := make([]byte, len(ecc.vrfSecKey))
	copy(seckey, ecc.vrfSecKey)
	ecc.lock.Unlock()

	header := block.Header()
	sealHash := ecc.SealHash(header).Bytes()

	prv, err := crypto.ToECDSA(seckey)
	if err != nil {
		log.Error("VCT: mine: invalid VRF key", "err", err)
		return
	}

	parameters, _ := setParameters(header)
	H := generateH(parameters)
	colInRow, rowInCol := generateQ(parameters, H)

	var (
		attempts int64
		nonce    = seed
		chainID  = ecc.chainIDBytes()
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

			var sigHash []byte
			if isVCT {
				sigHash = computeMiningSigMsgVCT(sealHash, nonce)
			} else {
				sigHash = computeMiningSigMsg(chainID, sealHash, nonce)
			}
			sigma, serr := crypto.Sign(sigHash, prv)
			if serr != nil {
				logger.Warn("VCT: mining sign failed", "err", serr)
				nonce++
				continue
			}

			var powSeed []byte
			if isVCT {
				powSeed = computePowSeedVCT(sealHash, nonce, sigma)
			} else {
				powSeed = computePowSeed(chainID, sealHash, nonce, sigma)
			}
			digest := crypto.Keccak512(powSeed)

			hv := generateHv(parameters, digest)
			hv, ow, _ := OptimizedDecoding(parameters, hv, H, rowInCol, colInRow)
			if ok, _ := MakeDecision(header, colInRow, ow); ok {
				header = types.CopyHeader(header)
				header.MixDigest = common.BytesToHash(digest)
				header.Nonce = types.EncodeNonce(nonce)
				header.Codeword = packCodeword(ow)
				header.VRFSignature = sigma
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

func (ecc *ECC) mine_seoul(block *types.Block, id int, seed uint64, abort chan struct{}, found chan *types.Block, isVCT bool) {
	ecc.lock.Lock()
	seckey := make([]byte, len(ecc.vrfSecKey))
	copy(seckey, ecc.vrfSecKey)
	ecc.lock.Unlock()

	header := block.Header()
	sealHash := ecc.SealHash(header).Bytes()

	prv, err := crypto.ToECDSA(seckey)
	if err != nil {
		log.Error("VCT: mine_seoul: invalid VRF key", "err", err)
		return
	}

	parameters, _ := setParameters_Seoul(header)
	H := generateH(parameters)
	colInRow, rowInCol := generateQ(parameters, H)

	var (
		attempts int64
		nonce    = seed
		chainID  = ecc.chainIDBytes()
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

			var sigHash []byte
			if isVCT {
				sigHash = computeMiningSigMsgVCT(sealHash, nonce)
			} else {
				sigHash = computeMiningSigMsg(chainID, sealHash, nonce)
			}
			sigma, serr := crypto.Sign(sigHash, prv)
			if serr != nil {
				logger.Warn("VCT: mining sign failed", "err", serr)
				nonce++
				continue
			}

			var powSeed []byte
			if isVCT {
				powSeed = computePowSeedVCT(sealHash, nonce, sigma)
			} else {
				powSeed = computePowSeed(chainID, sealHash, nonce, sigma)
			}
			digest := crypto.Keccak512(powSeed)

			hv := generateHv(parameters, digest)
			hv, ow, _ := OptimizedDecodingSeoul(parameters, hv, H, rowInCol, colInRow)
			if ok, _ := MakeDecision_Seoul(header, colInRow, ow); ok {
				header = types.CopyHeader(header)
				header.CodeLength = uint64(parameters.n)
				header.MixDigest = common.BytesToHash(digest)
				header.Nonce = types.EncodeNonce(nonce)
				header.Codeword = packCodeword(ow)
				header.VRFSignature = sigma
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

// ── Remote sealer ─────────────────────────────────────────────────────────────

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
	hash := s.ecc.SealHash(block.Header())
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
