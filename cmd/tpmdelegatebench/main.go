// tpmdelegatebench measures the complete TPM-authorize -> HTTP delegate ->
// ECCVCC evaluate pipeline. Worker servers never receive a TPM key handle;
// they receive only canonical message-signature pairs and public parameters.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cryptoecc/WorldLand/common"
	vct "github.com/cryptoecc/WorldLand/consensus/VCT"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
)

type delegatedRequest struct {
	Message   []byte `json:"message"`
	Signature []byte `json:"signature"`
}

type delegatedResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type job struct {
	request delegatedRequest
	started time.Time
}

type result struct {
	latency time.Duration
	success bool
	err     error
}

func main() {
	keyName := flag.String("key", "WorldLand-TPM-Work-Test", "existing non-exportable platform-TPM work key")
	attempts := flag.Int("n", 500, "number of distinct TPM-authorized work attempts")
	workers := flag.Int("workers", 1, "number of loopback HTTP delegated workers")
	workerDelay := flag.Duration("worker-delay", 0, "additional per-attempt delegation/worker delay")
	queueSize := flag.Int("queue", 32, "bounded signed-work queue size")
	flag.Parse()
	if *attempts <= 0 || *workers <= 0 || *queueSize <= 0 {
		fmt.Fprintln(os.Stderr, "-n, -workers and -queue must be positive")
		os.Exit(2)
	}

	signer, err := tpmwork.OpenPlatformSigner(*keyName, false)
	if err != nil {
		fatal(err)
	}
	defer signer.Close()
	header := &types.Header{Difficulty: vct.MinimumDifficulty}
	evaluator, err := vct.NewDelegatedWorkEvaluator(header, signer.PublicKey())
	if err != nil {
		fatal(err)
	}

	servers, endpoints, err := startWorkers(*workers, *workerDelay, evaluator)
	if err != nil {
		fatal(err)
	}
	defer func() {
		for _, server := range servers {
			_ = server.Close()
		}
	}()

	jobs := make(chan job, *queueSize)
	results := make(chan result, *attempts)
	var workerGroup sync.WaitGroup
	for workerID := 0; workerID < *workers; workerID++ {
		workerGroup.Add(1)
		go runWorker(endpoints[workerID], jobs, results, &workerGroup)
	}

	chainID := make([]byte, 32)
	chainID[30], chainID[31] = 0x65, 0x7e
	sealHash := make([]byte, 32)
	copy(sealHash, []byte("TGPoW delegated benchmark seal"))
	did := common.HexToHash("0x7467706f772d64656c656761746564")
	var vrfOutput [32]byte
	copy(vrfOutput[:], []byte("TGPoW delegated benchmark VRF"))
	signLatencies := make([]time.Duration, 0, *attempts)
	distinct := make(map[string]struct{}, *attempts)
	pipelineStarted := time.Now()
	for nonce := 0; nonce < *attempts; nonce++ {
		attemptStarted := time.Now()
		message := vct.TPMWorkMessage(chainID, sealHash, did, vrfOutput, uint64(nonce))
		signStarted := time.Now()
		signature, err := signer.SignDigest(message)
		signLatencies = append(signLatencies, time.Since(signStarted))
		if err != nil {
			fatal(fmt.Errorf("TPM authorization %d: %w", nonce, err))
		}
		distinct[string(message)] = struct{}{}
		jobs <- job{request: delegatedRequest{Message: message, Signature: signature}, started: attemptStarted}
	}
	close(jobs)
	workerGroup.Wait()
	close(results)
	elapsed := time.Since(pipelineStarted)

	e2eLatencies := make([]time.Duration, 0, *attempts)
	completed, successes, failures := 0, 0, 0
	for outcome := range results {
		completed++
		e2eLatencies = append(e2eLatencies, outcome.latency)
		if outcome.err != nil {
			failures++
		} else if outcome.success {
			successes++
		}
	}
	sort.Slice(signLatencies, func(i, j int) bool { return signLatencies[i] < signLatencies[j] })
	sort.Slice(e2eLatencies, func(i, j int) bool { return e2eLatencies[i] < e2eLatencies[j] })

	fmt.Printf("key=%s\n", *keyName)
	fmt.Printf("workers=%d\n", *workers)
	fmt.Printf("workerDelay=%s\n", *workerDelay)
	fmt.Printf("authorized=%d\n", *attempts)
	fmt.Printf("distinctInputs=%d\n", len(distinct))
	fmt.Printf("completed=%d\n", completed)
	fmt.Printf("evaluationFailures=%d\n", failures)
	fmt.Printf("puzzleSuccesses=%d\n", successes)
	fmt.Printf("elapsed=%s\n", elapsed)
	fmt.Printf("pipelinePerSecond=%.3f\n", float64(completed)/elapsed.Seconds())
	fmt.Printf("signP50=%s\n", percentile(signLatencies, 0.50))
	fmt.Printf("signP95=%s\n", percentile(signLatencies, 0.95))
	fmt.Printf("e2eP50=%s\n", percentile(e2eLatencies, 0.50))
	fmt.Printf("e2eP95=%s\n", percentile(e2eLatencies, 0.95))
}

func startWorkers(count int, delay time.Duration, evaluator *vct.DelegatedWorkEvaluator) ([]*http.Server, []string, error) {
	servers := make([]*http.Server, 0, count)
	endpoints := make([]string, 0, count)
	for i := 0; i < count; i++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, nil, err
		}
		var requests atomic.Uint64
		handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			requests.Add(1)
			defer request.Body.Close()
			var input delegatedRequest
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				writeResponse(response, delegatedResponse{Error: err.Error()})
				return
			}
			if delay > 0 {
				time.Sleep(delay)
			}
			success, err := evaluator.Evaluate(input.Message, input.Signature)
			if err != nil {
				writeResponse(response, delegatedResponse{Error: err.Error()})
				return
			}
			writeResponse(response, delegatedResponse{Success: success})
		})
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second}
		servers = append(servers, server)
		endpoints = append(endpoints, "http://"+listener.Addr().String())
		go func() { _ = server.Serve(listener) }()
	}
	return servers, endpoints, nil
}

func runWorker(endpoint string, jobs <-chan job, results chan<- result, group *sync.WaitGroup) {
	defer group.Done()
	client := &http.Client{Timeout: 10 * time.Second}
	for work := range jobs {
		encoded, err := json.Marshal(work.request)
		if err != nil {
			results <- result{latency: time.Since(work.started), err: err}
			continue
		}
		response, err := client.Post(endpoint, "application/json", bytes.NewReader(encoded))
		if err != nil {
			results <- result{latency: time.Since(work.started), err: err}
			continue
		}
		var output delegatedResponse
		err = json.NewDecoder(response.Body).Decode(&output)
		_ = response.Body.Close()
		if err == nil && output.Error != "" {
			err = fmt.Errorf("%s", output.Error)
		}
		results <- result{latency: time.Since(work.started), success: output.Success, err: err}
	}
}

func writeResponse(response http.ResponseWriter, output delegatedResponse) {
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(output)
}

func percentile(values []time.Duration, quantile float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	return values[int(float64(len(values)-1)*quantile)]
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
