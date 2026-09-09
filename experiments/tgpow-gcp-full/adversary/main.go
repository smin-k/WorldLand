// Bounded isolated-testnet adversary. Never exports private keys or contacts an
// endpoint other than the local node. Invalid enrollment must NOT be approved.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	ethereum "github.com/cryptoecc/WorldLand"
	"github.com/cryptoecc/WorldLand/accounts/abi/bind"
	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/ethclient"
	"log"
	"math/big"
	"os"
	"time"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
func emit(v interface{}) { b, e := json.Marshal(v); must(e); fmt.Println(string(b)) }
func main() {
	count := flag.Int("count", 3, "bounded request count, max 80")
	rate := flag.Int("rate", 1, "requests per second, max 8")
	validEvidence := flag.Bool("valid-evidence", false, "retain valid TPM static evidence, mismatch claimed identity (expensive rejection path)")
	flag.Parse()
	if *count < 1 || *count > 80 || *rate < 1 || *rate > 8 {
		log.Fatal("research bounds")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c, err := ethclient.DialContext(ctx, "http://127.0.0.1:8545")
	must(err)
	defer c.Close()
	chain, err := c.ChainID(ctx)
	must(err)
	if chain.Cmp(big.NewInt(103994)) != 0 {
		log.Fatal("unexpected chain")
	}
	var identity struct {
		Evidence tpmregistry.Evidence `json:"evidence"`
	}
	raw, err := os.ReadFile("/opt/worldland-testnet/identity.json")
	must(err)
	must(json.Unmarshal(raw, &identity))
	if *validEvidence {
		p := &tpmregistry.Policy{Version: 1, MaxEvidenceBytes: 1024 * 1024, AllowedProfileHashes: []common.Hash{crypto.Keccak256Hash(identity.Evidence.Profile)}}
		must(p.ConfigureCertificateProfile("gcp-cas-v1"))
		_, err = p.ValidateEvidence(chain, tpmregistry.DefaultRegistryAddress, &identity.Evidence)
		must(err)
	}
	sponsor, err := crypto.LoadECDSA("/opt/worldland-testnet/account.key")
	must(err)
	attacker, err := crypto.GenerateKey()
	must(err)
	from := crypto.PubkeyToAddress(sponsor.PublicKey)
	target := crypto.PubkeyToAddress(attacker.PublicKey)
	nonce, err := c.PendingNonceAt(ctx, from)
	must(err)
	price, err := c.SuggestGasPrice(ctx)
	must(err)
	funding := types.NewTransaction(nonce, target, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil), 21000, price, nil)
	signed, err := types.SignTx(funding, types.LatestSignerForChainID(chain), sponsor)
	must(err)
	must(c.SendTransaction(ctx, signed))
	receipt, err := bind.WaitMined(ctx, c, signed)
	must(err)
	if receipt.Status != 1 {
		log.Fatal("funding reverted")
	}
	registry, err := tpmregistry.NewRegistryClient(tpmregistry.DefaultRegistryAddress, c)
	must(err)
	auth, err := bind.NewKeyedTransactorWithChainID(attacker, chain)
	must(err)
	auth.Context = ctx
	auth.GasLimit = 1200000
	auth.GasPrice = price
	type item struct {
		Tx        *types.Transaction
		Submitted time.Time
		DID       common.Hash
		Request   common.Hash
		Variant   string
	}
	items := make([]item, 0, *count)
	start := time.Now()
	for i := 0; i < *count; i++ {
		due := start.Add(time.Duration(i) * time.Second / time.Duration(*rate))
		if d := time.Until(due); d > 0 {
			select {
			case <-time.After(d):
			case <-ctx.Done():
				must(ctx.Err())
			}
		}
		e := identity.Evidence
		variant := "corrupted-ek-signature"
		if *validEvidence {
			variant = "valid-static-evidence-wrong-claimed-identity"
		} else {
			switch i % 3 {
			case 0:
				e.EKCertificateDER = append([]byte(nil), e.EKCertificateDER...)
				e.EKCertificateDER[len(e.EKCertificateDER)-1] ^= 1
			case 1:
				variant = "wrong-profile"
				e.Profile = []byte("unauthorized research profile")
			case 2:
				variant = "malformed-attestation-key"
				e.AttestationPublicArea = []byte{0, 1, 2}
			}
		}
		bundle, err := e.CanonicalBytes()
		must(err)
		nullifier := crypto.Keccak256Hash(target.Bytes(), new(big.Int).SetInt64(int64(i)).Bytes())
		did := tpmregistry.DeriveDID(chain, tpmregistry.DefaultRegistryAddress, nullifier)
		data := tpmregistry.EnrollmentData{DID: did, DeviceNullifier: nullifier, WorkKeyHash: crypto.Keccak256Hash(e.WorkPublicKey), VRFKeyHash: crypto.Keccak256Hash(e.VRFPublicKey), ProfileHash: crypto.Keccak256Hash(e.Profile), EvidenceHash: crypto.Keccak256Hash(bundle)}
		auth.Nonce = big.NewInt(int64(i))
		submitted := time.Now()
		tx, err := registry.BeginProducer(auth, data, bundle)
		must(err)
		request := tpmregistry.DeriveRequestID(tpmregistry.DefaultRegistryAddress, chain, target, big.NewInt(int64(i)))
		items = append(items, item{tx, submitted, did, request, variant})
		emit(map[string]interface{}{"event": "submitted", "at": submitted, "tx": tx.Hash(), "request": request, "identity": did, "variant": variant, "submitMs": float64(time.Since(submitted).Microseconds()) / 1000})
	}
	for _, v := range items {
		receipt, err := bind.WaitMined(ctx, c, v.Tx)
		must(err)
		emit(map[string]interface{}{"event": "receipt", "at": time.Now(), "tx": v.Tx.Hash(), "request": v.Request, "identity": v.DID, "status": receipt.Status, "block": receipt.BlockNumber, "gas": receipt.GasUsed, "observedLatencyMs": time.Since(v.Submitted).Milliseconds()})
	}
	// Wait beyond every designated challenge slot; admission alone is not approval.
	last := uint64(0)
	for _, v := range items {
		s, err := registry.ProducerRequest(ctx, v.Request)
		must(err)
		if s.LastSlot > last {
			last = s.LastSlot
		}
	}
	for {
		h, err := c.BlockNumber(ctx)
		must(err)
		if h > last+2 {
			break
		}
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			must(ctx.Err())
		}
	}
	for _, v := range items {
		s, err := registry.ProducerRequest(ctx, v.Request)
		must(err)
		reg, err := registry.Registration(ctx, v.DID)
		must(err)
		logs, err := c.FilterLogs(ctx, ethereum.FilterQuery{FromBlock: big.NewInt(0), Addresses: []common.Address{tpmregistry.DefaultRegistryAddress}, Topics: [][]common.Hash{{tpmregistry.ProducerEventTopic("ProducerChallengePublished")}, {v.Request}}})
		must(err)
		emit(map[string]interface{}{"event": "verdict", "request": v.Request, "identity": v.DID, "approvals": s.Approvals, "challenges": len(logs), "active": reg.Active, "variant": v.Variant})
		if s.Approvals != 0 || len(logs) != 0 || reg.Active {
			log.Fatal("INVALID EVIDENCE PROGRESSED")
		}
	}
}
