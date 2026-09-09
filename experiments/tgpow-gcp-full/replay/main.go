// Broadcast bounded replay attempts on the isolated research chain only.
// Historical closed-request rejection is not active-window replay coverage.
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
	"time"
)

func must(e error) {
	if e != nil {
		log.Fatal(e)
	}
}
func emit(v interface{}) { b, e := json.Marshal(v); must(e); fmt.Println(string(b)) }
func main() {
	selected := flag.String("event", "all", "all, ProducerResponseSubmitted, or ProducerSlotApproved")
	openOnly := flag.Bool("open", false, "wait for a non-finalized 5-of-6 request after its slot window and before deadline")
	flag.Parse()
	if *selected != "all" && *selected != "ProducerResponseSubmitted" && *selected != "ProducerSlotApproved" {
		log.Fatal("invalid event")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c, e := ethclient.DialContext(ctx, "http://127.0.0.1:8545")
	must(e)
	defer c.Close()
	chain, e := c.ChainID(ctx)
	must(e)
	if chain.Cmp(big.NewInt(103994)) != 0 {
		log.Fatal("unexpected chain")
	}
	key, e := crypto.LoadECDSA("/opt/worldland-testnet/account.key")
	must(e)
	from := crypto.PubkeyToAddress(key.PublicKey)
	address := tpmregistry.DefaultRegistryAddress
	r, e := tpmregistry.NewRegistryClient(address, c)
	must(e)
	for _, event := range []string{"ProducerResponseSubmitted", "ProducerSlotApproved"} {
		if *selected != "all" && *selected != event {
			continue
		}
	retry:
		logs, e := c.FilterLogs(ctx, ethereum.FilterQuery{FromBlock: big.NewInt(0), Addresses: []common.Address{address}, Topics: [][]common.Hash{{tpmregistry.ProducerEventTopic(event)}}})
		must(e)
		found := false
		for index := len(logs) - 1; index >= 0; index-- {
			entry := logs[index]
			original, _, e := c.TransactionByHash(ctx, entry.TxHash)
			must(e)
			sender, e := types.Sender(types.LatestSignerForChainID(chain), original)
			must(e)
			if sender != from {
				continue
			}
			req := entry.Topics[1]
			before, e := r.ProducerRequest(ctx, req)
			must(e)
			if *openOnly {
				head, err := c.BlockNumber(ctx)
				must(err)
				state, err := r.Request(ctx, req)
				must(err)
				if state.Finalized || before.Approvals != 5 || head <= before.LastSlot || head+10 >= before.ResponseDeadline {
					continue
				}
			}
			found = true
			nonce, e := c.PendingNonceAt(ctx, from)
			must(e)
			price, e := c.SuggestGasPrice(ctx)
			must(e)
			data := original.Data()
			_, probe := c.CallContract(ctx, ethereum.CallMsg{From: from, To: &address, Gas: 1200000, Data: data}, nil)
			reason := "accepted"
			if probe != nil {
				reason = probe.Error()
			}
			tx := types.NewTransaction(nonce, address, big.NewInt(0), 1200000, price, data)
			signed, e := types.SignTx(tx, types.LatestSignerForChainID(chain), key)
			must(e)
			must(c.SendTransaction(ctx, signed))
			receipt, e := bind.WaitMined(ctx, c, signed)
			must(e)
			after, e := r.ProducerRequest(ctx, req)
			must(e)
			scope := "historical-request duplicate calldata with fresh transaction nonce"
			if *openOnly {
				scope = "open 5-of-6 request duplicate calldata with fresh nonce"
				state, err := r.Request(ctx, req)
				must(err)
				if state.Finalized || receipt.BlockNumber.Uint64() > before.ResponseDeadline {
					log.Fatal("request closed before replay receipt; not active-window coverage")
				}
			}
			emit(map[string]interface{}{"case": event, "scope": scope, "sourceTx": original.Hash(), "tx": signed.Hash(), "request": req, "status": receipt.Status, "block": receipt.BlockNumber, "ethCall": reason, "before": before, "after": after})
			if receipt.Status != 0 || before != after {
				log.Fatal("REPLAY ACCEPTED OR REQUEST CHANGED")
			}
			break
		}
		if !found {
			if *openOnly {
				select {
				case <-ctx.Done():
					log.Fatal(ctx.Err())
				case <-time.After(time.Second):
					goto retry
				}
			}
			log.Fatal("no locally owned canonical source for " + event)
		}
	}
}
