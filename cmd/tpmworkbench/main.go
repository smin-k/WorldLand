// tpmworkbench measures the persisted platform-TPM work key used by WorldLand.
// It never clears the TPM or deletes keys. Key creation occurs only with
// -create and leaves the named non-exportable key available for later mining.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
)

func main() {
	keyName := flag.String("key", "WorldLand-TPM-Work-Test", "persisted platform-TPM work key name")
	create := flag.Bool("create", false, "create the non-exportable TPM key if missing")
	iterations := flag.Int("n", 100, "number of sequential signatures")
	flag.Parse()
	if *iterations <= 0 {
		fmt.Fprintln(os.Stderr, "-n must be positive")
		os.Exit(2)
	}

	signer, err := tpmwork.OpenPlatformSigner(*keyName, *create)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer signer.Close()

	latencies := make([]time.Duration, 0, *iterations)
	started := time.Now()
	for nonce := 0; nonce < *iterations; nonce++ {
		var input [8]byte
		binary.BigEndian.PutUint64(input[:], uint64(nonce))
		digest := sha256.Sum256(append([]byte("WORLDLAND_TPM_BENCH_V1"), input[:]...))
		before := time.Now()
		signature, err := signer.SignDigest(digest[:])
		latencies = append(latencies, time.Since(before))
		if err != nil {
			fmt.Fprintf(os.Stderr, "signature %d failed: %v\n", nonce, err)
			os.Exit(1)
		}
		if !tpmwork.VerifyDigest(signer.PublicKey(), digest[:], signature) {
			fmt.Fprintf(os.Stderr, "signature %d did not verify\n", nonce)
			os.Exit(1)
		}
	}
	elapsed := time.Since(started)
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	fmt.Printf("key=%s\n", *keyName)
	fmt.Printf("publicKey=%s\n", hex.EncodeToString(signer.PublicKey()))
	if probe, ok := interface{}(signer).(tpmwork.PrivateExportProbe); ok {
		policy, err := probe.PrivateKeyExportPolicy()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read private-key export policy: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("privateKeyExportPolicy=0x%08x\n", policy)
		blocked, status := probe.PrivateKeyExportBlocked()
		fmt.Printf("privateKeyExportBlocked=%t\n", blocked)
		fmt.Printf("privateKeyExportStatus=0x%08x\n", status)
	}
	fmt.Printf("signatures=%d\n", *iterations)
	fmt.Printf("elapsed=%s\n", elapsed)
	fmt.Printf("signaturesPerSecond=%.3f\n", float64(*iterations)/elapsed.Seconds())
	fmt.Printf("latencyP50=%s\n", percentile(latencies, 0.50))
	fmt.Printf("latencyP95=%s\n", percentile(latencies, 0.95))
	fmt.Printf("latencyP99=%s\n", percentile(latencies, 0.99))
}

func percentile(values []time.Duration, quantile float64) time.Duration {
	index := int(float64(len(values)-1) * quantile)
	return values[index]
}
