// Read-only audit of a clean, PUBLIC chaindata backup. Never opens a live VM DB.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/core/rawdb"
	"log"
)

func main() {
	path := flag.String("db", "", "public copied chaindata")
	first := flag.Uint64("first", 15, "first height")
	last := flag.Uint64("last", 40, "last height, max 1000")
	flag.Parse()
	if *path == "" || *last > 1000 || *first > *last {
		log.Fatal("invalid bounds")
	}
	db, err := rawdb.NewLevelDBDatabase(*path, 32, 16, "", true)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	config := rawdb.ReadChainConfig(db, rawdb.ReadCanonicalHash(db, 0))
	if config == nil {
		log.Fatal("no chain config")
	}
	for n := *first; n <= *last; n++ {
		canonical := rawdb.ReadCanonicalHash(db, n)
		for _, hash := range rawdb.ReadAllHashes(db, n) {
			if hash == canonical {
				continue
			}
			block := rawdb.ReadBlock(db, hash, n)
			if block == nil {
				continue
			}
			events := []interface{}{}
			receipts := rawdb.ReadReceipts(db, hash, n, config)
			for _, receipt := range receipts {
				for _, entry := range receipt.Logs {
					if entry.Address != tpmregistry.DefaultRegistryAddress {
						continue
					}
					events = append(events, map[string]interface{}{"topics": entry.Topics, "tx": entry.TxHash})
				}
			}
			v := map[string]interface{}{"height": n, "orphan": hash, "parent": block.ParentHash(), "canonical": canonical, "transactions": len(block.Transactions()), "registryEvents": events}
			b, e := json.Marshal(v)
			if e != nil {
				log.Fatal(e)
			}
			fmt.Println(string(b))
		}
	}
}
