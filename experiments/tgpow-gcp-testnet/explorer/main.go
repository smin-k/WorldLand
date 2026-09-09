// explorer exposes only fixed read-only observations, never a general RPC proxy.
package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/crypto"
)

//go:embed index.html
var index []byte

//go:embed app.js
var app []byte

//go:embed style.css
var style []byte

type identity struct {
	Controller string `json:"controller"`
	DID        string `json:"did"`
}
type manifest struct {
	ChainID           int        `json:"chainId"`
	Identities        []identity `json:"identities"`
	BootstrapCount    int        `json:"bootstrapCount"`
	ProducerSlots     int        `json:"producerSlots"`
	ProducerThreshold int        `json:"producerThreshold"`
	ActivationDelay   int        `json:"activationDelay"`
	ObserverEndpoints []string   `json:"observerEndpoints"`
}
type registration struct {
	Controller string `json:"controller"`
	DID        string `json:"did"`
	Bootstrap  bool   `json:"bootstrap"`
	Registered bool   `json:"registered"`
	Active     bool   `json:"active"`
}
type snapshot struct {
	Node          int                      `json:"node"`
	Time          time.Time                `json:"time"`
	Height        uint64                   `json:"height"`
	Hash          string                   `json:"hash"`
	Peers         uint64                   `json:"peers"`
	Mining        bool                     `json:"mining"`
	Error         string                   `json:"error,omitempty"`
	Registrations []registration           `json:"registrations"`
	Blocks        []map[string]interface{} `json:"blocks"`
}

var httpClient = &http.Client{Timeout: 4 * time.Second}

func rpc(method string, params interface{}, target interface{}) error {
	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequestWithContext(context.Background(), "POST", "http://127.0.0.1:8545", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var result struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4*1024*1024)).Decode(&result); err != nil {
		return err
	}
	if len(result.Error) > 0 && string(result.Error) != "null" {
		return fmt.Errorf("RPC error: %s", result.Error)
	}
	return json.Unmarshal(result.Result, target)
}

func collect(n int, m manifest) snapshot {
	s := snapshot{Node: n, Time: time.Now().UTC()}
	var height, peers string
	if err := rpc("eth_blockNumber", []interface{}{}, &height); err != nil {
		s.Error = "Node RPC unavailable"
		return s
	}
	s.Height, _ = strconv.ParseUint(height[2:], 16, 64)
	if err := rpc("net_peerCount", []interface{}{}, &peers); err != nil {
		s.Error = err.Error()
		return s
	}
	s.Peers, _ = strconv.ParseUint(peers[2:], 16, 64)
	if err := rpc("eth_mining", []interface{}{}, &s.Mining); err != nil {
		s.Error = err.Error()
		return s
	}
	var head map[string]interface{}
	if err := rpc("eth_getBlockByNumber", []interface{}{height, false}, &head); err != nil {
		s.Error = err.Error()
		return s
	}
	s.Hash, _ = head["hash"].(string)
	for i, id := range m.Identities {
		did := common.HexToHash(id.DID)
		base := crypto.Keccak256Hash(did[:], make([]byte, 32)).Big()
		read := func(offset int64) (bool, error) {
			slot := common.BigToHash(new(big.Int).Add(base, big.NewInt(offset)))
			var value string
			err := rpc("eth_getStorageAt", []interface{}{"0x0000000000000000000000000000000000000801", slot.Hex(), height}, &value)
			return common.HexToHash(value) != (common.Hash{}), err
		}
		registered, err := read(1)
		if err != nil {
			s.Error = err.Error()
			return s
		}
		active, err := read(5)
		if err != nil {
			s.Error = err.Error()
			return s
		}
		s.Registrations = append(s.Registrations, registration{id.Controller, id.DID, i < m.BootstrapCount, registered, active})
	}
	if n == 1 {
		for i := uint64(0); i < 20 && i <= s.Height; i++ {
			var block map[string]interface{}
			if err := rpc("eth_getBlockByNumber", []interface{}{fmt.Sprintf("0x%x", s.Height-i), false}, &block); err != nil {
				s.Error = err.Error()
				break
			}
			s.Blocks = append(s.Blocks, block)
		}
	}
	return s
}

func main() {
	n := flag.Int("node", 1, "node number")
	input := flag.String("manifest", "/opt/worldland-testnet/manifest.json", "public experiment manifest")
	listen := flag.String("listen", ":8081", "observation server")
	public := flag.Bool("public", false, "also serve explorer UI on port 8080")
	flag.Parse()
	raw, err := os.ReadFile(*input)
	if err != nil {
		log.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		log.Fatal(err)
	}
	if len(m.Identities) < 2 || *n < 1 || *n > len(m.Identities) || m.BootstrapCount < 1 || m.BootstrapCount >= len(m.Identities) {
		log.Fatal("invalid experiment manifest/node")
	}
	var mu sync.RWMutex
	current := snapshot{Node: *n, Error: "Starting", Time: time.Now().UTC()}
	go func() {
		for {
			next := collect(*n, m)
			mu.Lock()
			current = next
			mu.Unlock()
			time.Sleep(5 * time.Second)
		}
	}()
	send := func(w http.ResponseWriter, r *http.Request, v interface{}) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/node", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		mu.RLock()
		s := current
		mu.RUnlock()
		send(w, r, s)
	})
	if *public {
		endpoints := m.ObserverEndpoints
		if len(endpoints) != len(m.Identities) {
			log.Fatal("observer endpoint count must match identities")
		}
		var aggregateMu sync.RWMutex
		aggregate := make([]snapshot, len(endpoints))
		go func() {
			for {
				next := make([]snapshot, len(endpoints))
				var wg sync.WaitGroup
				for i, url := range endpoints {
					wg.Add(1)
					go func(i int, url string) {
						defer wg.Done()
						next[i] = snapshot{Node: i + 1, Error: "Observation unavailable", Time: time.Now().UTC()}
						res, err := httpClient.Get(url)
						if err != nil {
							return
						}
						defer res.Body.Close()
						var item snapshot
						if json.NewDecoder(io.LimitReader(res.Body, 4*1024*1024)).Decode(&item) == nil {
							next[i] = item
						}
					}(i, url)
				}
				wg.Wait()
				aggregateMu.Lock()
				aggregate = next
				aggregateMu.Unlock()
				time.Sleep(5 * time.Second)
			}
		}()
		mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				w.WriteHeader(405)
				return
			}
			aggregateMu.RLock()
			copyValue := append([]snapshot{}, aggregate...)
			aggregateMu.RUnlock()
			send(w, r, map[string]interface{}{"chainId": m.ChainID, "nodes": copyValue, "bootstrapCount": m.BootstrapCount, "producerSlots": m.ProducerSlots, "producerThreshold": m.ProducerThreshold, "activationDelay": m.ActivationDelay})
		})
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				w.WriteHeader(405)
				return
			}
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'")
			switch r.URL.Path {
			case "/":
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write(index)
			case "/app.js":
				w.Header().Set("Content-Type", "application/javascript")
				w.Write(app)
			case "/style.css":
				w.Header().Set("Content-Type", "text/css")
				w.Write(style)
			default:
				http.NotFound(w, r)
			}
		})
		go func() {
			log.Fatal((&http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}).ListenAndServe())
		}()
	}
	log.Fatal((&http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}).ListenAndServe())
}
