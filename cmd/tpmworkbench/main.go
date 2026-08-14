// tpmworkbench measures the persisted platform-TPM work key used by WorldLand.
// It never clears the TPM or deletes keys. Key creation occurs only with
// -create and leaves the named non-exportable key available for later mining.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
	probeEvidence := flag.Bool("evidence", false, "print read-only platform and key attestation properties")
	probeAttestationEvidence := flag.Bool("aikevidence", false, "print read-only identity-binding properties for -aik")
	certify := flag.Bool("certify", false, "create and locally verify a nonce-bound TPM2_Certify proof")
	attestationKey := flag.String("aik", "WorldLand-TPM-AIK-Test", "persisted restricted TPM attestation-key name")
	createAttestationKey := flag.Bool("aikcreate", false, "create the restricted TPM attestation key if missing")
	printCertification := flag.Bool("certjson", false, "print the portable key-certification JSON")
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
	if *probeEvidence {
		if probe, ok := interface{}(signer).(tpmwork.PlatformEvidenceProbe); ok {
			for _, property := range probe.ProbePlatformEvidence() {
				if property.Status != 0 {
					fmt.Printf("evidence[%s.%s]=status:0x%08x\n", property.Scope, property.Name, property.Status)
					continue
				}
				fmt.Printf("evidence[%s.%s]=bytes:%d hex:%s\n", property.Scope, property.Name, len(property.Value), hex.EncodeToString(property.Value))
			}
		}
	}
	if *probeAttestationEvidence {
		if probe, ok := interface{}(signer).(tpmwork.PlatformEvidenceProbe); ok {
			for _, property := range probe.ProbeAttestationKeyEvidence(*attestationKey) {
				if property.Status != 0 {
					fmt.Printf("evidence[%s.%s]=status:0x%08x\n", property.Scope, property.Name, property.Status)
					continue
				}
				fmt.Printf("evidence[%s.%s]=bytes:%d hex:%s\n", property.Scope, property.Name, len(property.Value), hex.EncodeToString(property.Value))
			}
		}
	}
	if *certify {
		challenge := sha256.Sum256([]byte("WORLDLAND_TPM_ATTESTATION_PROBE_V1"))
		if certifier, ok := interface{}(signer).(tpmwork.KeyCertifier); ok {
			certification, err := certifier.CertifyWorkKey(*attestationKey, *createAttestationKey, challenge[:])
			if err != nil {
				fmt.Fprintf(os.Stderr, "TPM key certification failed: %v\n", err)
				os.Exit(1)
			}
			if err := tpmwork.VerifyKeyCertification(certification); err != nil {
				fmt.Fprintf(os.Stderr, "TPM key certification did not verify: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("attestationKey=%s\n", *attestationKey)
			fmt.Printf("attestationChallenge=%s\n", hex.EncodeToString(challenge[:]))
			fmt.Printf("certificationVerified=true\n")
			fmt.Printf("workPublicAreaBytes=%d\n", len(certification.WorkPublicArea))
			fmt.Printf("attestationPublicAreaBytes=%d\n", len(certification.AttestationPublicArea))
			fmt.Printf("attestationStatementBytes=%d\n", len(certification.AttestationStatement))
			fmt.Printf("attestationSignatureBytes=%d\n", len(certification.AttestationSignature))
			if *printCertification {
				encoded, err := json.Marshal(certification)
				if err != nil {
					fmt.Fprintf(os.Stderr, "encode certification JSON: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("certificationJSON=%s\n", encoded)
			}
		} else {
			fmt.Fprintln(os.Stderr, "TPM key certification is not supported on this platform")
			os.Exit(1)
		}
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
