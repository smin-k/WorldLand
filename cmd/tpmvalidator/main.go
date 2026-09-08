package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/ethclient"
)

type repeatedFlag []string

func (values *repeatedFlag) String() string { return strings.Join(*values, ",") }
func (values *repeatedFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	var roots repeatedFlag
	var profiles repeatedFlag
	listen := flag.String("listen", "127.0.0.1:8741", "HTTP listen address")
	rpcURL := flag.String("rpc", "", "WorldLand JSON-RPC URL")
	registryHex := flag.String("registry", "0x0000000000000000000000000000000000000801", "registry address")
	chainIDValue := flag.Int64("chain-id", 0, "chain ID")
	keyFile := flag.String("signing-key", "", "validator secp256k1 private-key file")
	printPolicy := flag.Bool("print-policy-digest", false, "print the configured policy digest and exit")
	requireEKOID := flag.Bool("require-ek-oid", true, "require tcg-kp-EKCertificate extended key usage")
	certificateProfile := flag.String("certificate-profile", tpmregistry.CertificateProfileManufacturer, "EK certificate policy: manufacturer or gcp-cas-v1 (pinned Google root)")
	maxEvidence := flag.Uint64("max-evidence-bytes", 1024*1024, "maximum canonical evidence size")
	maxSessions := flag.Int("max-sessions", 4096, "maximum concurrent activation sessions")
	sessionTTL := flag.Duration("session-ttl", 5*time.Minute, "activation session lifetime")
	insecureNoRPC := flag.Bool("insecure-no-rpc-check", false, "allow signing without checking beginRegistration on chain")
	tlsCertificate := flag.String("tls-cert", "", "TLS certificate PEM")
	tlsKey := flag.String("tls-key", "", "TLS private key PEM")
	flag.Var(&roots, "ek-root", "trusted EK root certificate PEM/DER (repeatable)")
	flag.Var(&profiles, "profile-hash", "allowed 32-byte profile hash (repeatable)")
	flag.Parse()

	if len(roots) == 0 && *certificateProfile == tpmregistry.CertificateProfileManufacturer {
		flag.Usage()
		log.Fatal("at least one ek-root is required")
	}
	certificates, err := loadCertificates(roots)
	if err != nil {
		log.Fatal(err)
	}
	allowedProfiles := make([]common.Hash, len(profiles))
	for i, value := range profiles {
		decoded, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
		if err != nil || len(decoded) != common.HashLength {
			log.Fatalf("invalid profile hash %q", value)
		}
		allowedProfiles[i] = common.BytesToHash(decoded)
	}
	policy := &tpmregistry.Policy{
		Version: tpmregistry.EvidenceVersion, RootCertificates: certificates,
		RequireEKCertificateOID: *requireEKOID, MaxEvidenceBytes: *maxEvidence,
		AllowedProfileHashes: allowedProfiles,
	}
	if err := policy.ConfigureCertificateProfile(*certificateProfile); err != nil {
		log.Fatal(err)
	}
	if *printPolicy {
		digest, err := policy.Digest()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(digest)
		return
	}
	if *chainIDValue <= 0 || *keyFile == "" || !common.IsHexAddress(*registryHex) {
		flag.Usage()
		log.Fatal("chain-id, signing-key and a valid registry are required")
	}
	keyBytes, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	keyHex := strings.TrimPrefix(strings.TrimSpace(string(keyBytes)), "0x")
	key, err := crypto.HexToECDSA(keyHex)
	if err != nil {
		log.Fatalf("invalid validator signing key: %v", err)
	}

	var requestVerifier tpmregistry.RequestVerifier
	if !*insecureNoRPC {
		if *rpcURL == "" {
			log.Fatal("rpc is required unless insecure-no-rpc-check is set")
		}
		client, err := ethclient.Dial(*rpcURL)
		if err != nil {
			log.Fatal(err)
		}
		requestVerifier, err = tpmregistry.NewRPCRequestVerifier(client, common.HexToAddress(*registryHex))
		if err != nil {
			log.Fatal(err)
		}
	}
	service, err := tpmregistry.NewValidatorService(tpmregistry.ValidatorConfig{
		ChainID: big.NewInt(*chainIDValue), Registry: common.HexToAddress(*registryHex),
		Policy:     policy,
		SigningKey: key, RequestVerifier: requestVerifier,
		AllowUnverifiedRequest: *insecureNoRPC, SessionTTL: *sessionTTL,
		MaxSessions: *maxSessions,
	})
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr: *listen, Handler: service.Handler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute,
	}
	log.Printf("TPM validator %s listening on %s (policy %s)", service.Address(), *listen, service.PolicyDigest())
	if (*tlsCertificate == "") != (*tlsKey == "") {
		log.Fatal("tls-cert and tls-key must be set together")
	}
	if *tlsCertificate != "" {
		log.Fatal(server.ListenAndServeTLS(*tlsCertificate, *tlsKey))
	}
	log.Print("warning: serving plaintext HTTP; use only on a trusted network or behind TLS")
	log.Fatal(server.ListenAndServe())
}

func loadCertificates(paths []string) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	for _, path := range paths {
		encoded, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		remaining := encoded
		foundPEM := false
		for {
			block, rest := pem.Decode(remaining)
			if block == nil {
				break
			}
			remaining = rest
			if block.Type != "CERTIFICATE" {
				continue
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
			certificates = append(certificates, certificate)
			foundPEM = true
		}
		if !foundPEM {
			certificate, err := x509.ParseCertificate(encoded)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
			certificates = append(certificates, certificate)
		}
	}
	return certificates, nil
}
