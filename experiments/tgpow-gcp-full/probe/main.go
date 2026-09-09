// Read-only live registry audit. eth_call executes against actual node state;
// it does not broadcast a transaction or require any private key.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	ethereum "github.com/cryptoecc/WorldLand"
	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/ethclient"
	"log"
	"math/big"
	"time"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := ethclient.DialContext(ctx, "http://127.0.0.1:8545")
	must(err)
	defer c.Close()
	chain, err := c.ChainID(ctx)
	must(err)
	if chain.Cmp(big.NewInt(103994)) != 0 {
		log.Fatal("unexpected chain")
	}
	h, err := c.HeaderByNumber(ctx, nil)
	must(err)
	address := tpmregistry.DefaultRegistryAddress
	r, err := tpmregistry.NewRegistryClient(address, c)
	must(err)
	logs, err := c.FilterLogs(ctx, ethereum.FilterQuery{FromBlock: big.NewInt(0), ToBlock: h.Number, Addresses: []common.Address{address}, Topics: [][]common.Hash{{tpmregistry.ProducerEventTopic("ProducerRegistrationRequested")}}})
	must(err)
	for _, entry := range logs {
		e, err := tpmregistry.ParseProducerRegistrationEvent(entry)
		must(err)
		evidence, err := tpmregistry.DecodeEvidence(e.EvidenceBundle)
		must(err)
		p := &tpmregistry.Policy{Version: 1, MaxEvidenceBytes: 1024 * 1024, AllowedProfileHashes: []common.Hash{crypto.Keccak256Hash(evidence.Profile)}}
		must(p.ConfigureCertificateProfile("gcp-cas-v1"))
		v, err := p.ValidateEvidence(chain, address, evidence)
		if err != nil {
			state, stateErr := r.ProducerRequest(ctx, e.RequestID)
			must(stateErr)
			encoded, encodeErr := json.Marshal(map[string]interface{}{"request": e.RequestID, "evidenceError": err.Error(), "producerRequest": state})
			must(encodeErr)
			fmt.Println(string(encoded))
			continue
		}
		request, err := r.ProducerRequest(ctx, e.RequestID)
		must(err)
		state, err := r.Request(ctx, e.RequestID)
		must(err)
		registration, err := r.Registration(ctx, e.Identity)
		must(err)
		data := tpmregistry.EnrollmentData{DID: v.DID, WorkKeyHash: v.WorkKeyHash, VRFKeyHash: v.VRFKeyHash, ProfileHash: v.ProfileHash, DeviceNullifier: v.DeviceNullifier, EvidenceHash: v.EvidenceHash}
		call, err := tpmregistry.PackRegistryCall("finalizeProducerRegistration", e.RequestID, data)
		must(err)
		_, callErr := c.CallContract(ctx, ethereum.CallMsg{From: state.Controller, To: &address, Gas: 3000000, Data: call}, h.Number)
		reason := "accepted"
		if callErr != nil {
			reason = callErr.Error()
		}
		encoded, err := json.Marshal(map[string]interface{}{"head": h.Number, "headHash": h.Hash(), "request": e.RequestID, "identity": e.Identity, "producerRequest": request, "finalized": state.Finalized, "active": registration.Active, "finalizeEthCall": reason})
		must(err)
		fmt.Println(string(encoded))
	}
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
