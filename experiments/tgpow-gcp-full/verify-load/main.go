// Bounded closed-loop cryptographic verification benchmark using real on-chain
// TPM evidence. This is NOT a stream of new accepted enrollment transactions.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	ethereum "github.com/cryptoecc/WorldLand"
	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/ethclient"
	"log"
	"math/big"
	"runtime"
	"sort"
	"sync"
	"time"
)

type fixture struct {
	initial   *tpmregistry.Evidence
	challenge common.Hash
	response  []byte
	request   common.Hash
	slot      uint64
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
func main() {
	workers := flag.Int("workers", 1, "bounded workers 1..8")
	seconds := flag.Int("seconds", 30, "bounded measurement seconds 10..60")
	mode := flag.String("mode", "response", "response or admission")
	flag.Parse()
	if *workers < 1 || *workers > 8 || *seconds < 10 || *seconds > 60 || (*mode != "response" && *mode != "admission") {
		log.Fatal("invalid bounds")
	}
	runtime.GOMAXPROCS(2)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c, err := ethclient.DialContext(ctx, "http://127.0.0.1:8545")
	must(err)
	defer c.Close()
	chain, err := c.ChainID(ctx)
	must(err)
	if chain.Cmp(big.NewInt(103994)) != 0 {
		log.Fatal("wrong chain")
	}
	address := tpmregistry.DefaultRegistryAddress
	r, err := tpmregistry.NewRegistryClient(address, c)
	must(err)
	head, err := c.BlockNumber(ctx)
	must(err)
	entries, err := c.FilterLogs(ctx, ethereum.FilterQuery{FromBlock: big.NewInt(0), ToBlock: new(big.Int).SetUint64(head), Addresses: []common.Address{address}, Topics: [][]common.Hash{{tpmregistry.ProducerEventTopic("ProducerRegistrationRequested")}}})
	must(err)
	var fixtures []fixture
	var policy *tpmregistry.Policy
	for _, entry := range entries {
		event, err := tpmregistry.ParseProducerRegistrationEvent(entry)
		must(err)
		initial, err := tpmregistry.DecodeEvidence(event.EvidenceBundle)
		must(err)
		p := &tpmregistry.Policy{Version: 1, MaxEvidenceBytes: 1024 * 1024, AllowedProfileHashes: []common.Hash{crypto.Keccak256Hash(initial.Profile)}}
		must(p.ConfigureCertificateProfile("gcp-cas-v1"))
		if _, err = p.ValidateEvidence(chain, address, initial); err != nil {
			continue
		}
		responses, err := c.FilterLogs(ctx, ethereum.FilterQuery{FromBlock: big.NewInt(0), ToBlock: new(big.Int).SetUint64(head), Addresses: []common.Address{address}, Topics: [][]common.Hash{{tpmregistry.ProducerEventTopic("ProducerResponseSubmitted")}, {event.RequestID}}})
		must(err)
		for _, entry := range responses {
			response, err := tpmregistry.ParseProducerResponseEvent(entry)
			must(err)
			slot, err := r.ProducerSlot(ctx, event.RequestID, response.Slot)
			must(err)
			challenge := tpmregistry.ProducerCertifyChallenge(chain, address, event.RequestID, response.Slot, slot.Commitment)
			if tpmregistry.VerifyProducerResponseEvidence(initial, challenge[:], response.EvidenceBundle) != nil {
				continue
			}
			fixtures = append(fixtures, fixture{initial, challenge, response.EvidenceBundle, event.RequestID, response.Slot})
			policy = p
		}
		if len(fixtures) >= 12 {
			break
		}
	}
	if len(fixtures) == 0 {
		log.Fatal("no cryptographically valid real TPM fixtures")
	}
	verify := func(f fixture) error {
		if *mode == "admission" {
			_, e := policy.ValidateEvidence(chain, address, f.initial)
			return e
		}
		return tpmregistry.VerifyProducerResponseEvidence(f.initial, f.challenge[:], f.response)
	}
	for _, f := range fixtures {
		must(verify(f))
	}
	start := time.Now()
	deadline := start.Add(time.Duration(*seconds) * time.Second)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var samples []int64
	var count, failures uint64
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			var local []int64
			var n, bad uint64
			for time.Now().Before(deadline) {
				f := fixtures[(int(n)+offset)%len(fixtures)]
				t := time.Now()
				e := verify(f)
				elapsed := time.Since(t).Nanoseconds()
				n++
				if e != nil {
					bad++
				}
				if len(local) < 200000 {
					local = append(local, elapsed)
				}
			}
			mu.Lock()
			samples = append(samples, local...)
			count += n
			failures += bad
			mu.Unlock()
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	quantile := func(q float64) float64 { return float64(samples[int(float64(len(samples)-1)*q)]) / 1e6 }
	endHead, err := c.BlockNumber(ctx)
	must(err)
	out := map[string]interface{}{"scope": "closed-loop real-evidence verification component; no new registration transactions", "mode": *mode, "workers": *workers, "gomaxprocs": 2, "seconds": elapsed, "validFixtures": len(fixtures), "operations": count, "failures": failures, "opsPerSecond": float64(count) / elapsed, "latencySampleCount": len(samples), "p50ms": quantile(.5), "p95ms": quantile(.95), "p99ms": quantile(.99), "startHead": head, "endHead": endHead}
	raw, err := json.Marshal(out)
	must(err)
	fmt.Println(string(raw))
	if failures != 0 {
		log.Fatal("valid fixture verification failures")
	}
}
