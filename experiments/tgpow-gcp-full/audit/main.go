// audit summarizes canonical registry events without handling private keys.
package main

import (
	"encoding/json"
	"fmt"
	"github.com/cryptoecc/WorldLand/accounts/abi"
	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
	"log"
	"math/big"
	"os"
	"sort"
	"strings"
)

type request struct {
	ID                                          common.Hash
	First, Last, Deadline                       uint64
	Challenges, Responses, Approvals            []uint64
	Finalized                                   bool
	BeginBlock, FinalizedBlock, ActivationBlock uint64
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: audit registry-logs.json")
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	var data struct {
		Result []types.Log
		Error  json.RawMessage
	}
	if err = json.Unmarshal(raw, &data); err != nil {
		log.Fatal(err)
	}
	if len(data.Error) > 0 && string(data.Error) != "null" {
		log.Fatal(string(data.Error))
	}
	parsed, err := abi.JSON(strings.NewReader(tpmregistry.RegistryABI))
	if err != nil {
		log.Fatal(err)
	}
	names := map[common.Hash]string{}
	for name, event := range parsed.Events {
		names[event.ID] = name
	}
	for _, name := range []string{"ProducerRegistrationRequested", "ProducerChallengePublished", "ProducerResponseSubmitted", "ProducerSlotApproved"} {
		names[tpmregistry.ProducerEventTopic(name)] = name
	}
	names[crypto.Keccak256Hash([]byte("RegistrationFinalized(bytes32,bytes32,address,uint256)"))] = "RegistrationFinalized"
	requests := map[common.Hash]*request{}
	for _, entry := range data.Result {
		if entry.Removed || len(entry.Topics) < 2 {
			continue
		}
		id := entry.Topics[1]
		name := names[entry.Topics[0]]
		if name == "ProducerRegistrationRequested" {
			e, err := tpmregistry.ParseProducerRegistrationEvent(entry)
			if err != nil {
				log.Fatal(err)
			}
			requests[id] = &request{ID: id, First: e.FirstSlot, Last: e.LastSlot, Deadline: e.ResponseDeadline, BeginBlock: entry.BlockNumber}
			continue
		}
		r := requests[id]
		if r == nil {
			continue
		}
		switch name {
		case "ProducerChallengePublished":
			r.Challenges = append(r.Challenges, entry.Topics[2].Big().Uint64())
		case "ProducerResponseSubmitted":
			r.Responses = append(r.Responses, entry.Topics[2].Big().Uint64())
		case "ProducerSlotApproved":
			r.Approvals = append(r.Approvals, entry.Topics[2].Big().Uint64())
		case "RegistrationFinalized":
			if len(entry.Data) != 32 || !new(big.Int).SetBytes(entry.Data).IsUint64() {
				log.Fatal("invalid activation block encoding")
			}
			r.Finalized = true
			r.FinalizedBlock = entry.BlockNumber
			r.ActivationBlock = new(big.Int).SetBytes(entry.Data).Uint64()
		}
	}
	ids := []string{}
	for id := range requests {
		ids = append(ids, id.Hex())
	}
	sort.Strings(ids)
	for _, id := range ids {
		raw, _ := json.Marshal(requests[common.HexToHash(id)])
		fmt.Println(string(raw))
	}
}
