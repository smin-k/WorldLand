package tpmproducer

import (
	"context"
	"errors"
	"math/big"
	"sync"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/ethclient"
	"github.com/cryptoecc/WorldLand/rpc"
)

// Config contains paths to local credentials, never credential contents.
type Config struct {
	KeyFile            string
	CertificateProfile string
	EKRoots            []string
	ProfileHashes      []common.Hash
	Lookback           uint64
	MaxPerSlot         int
	GasLimit           uint64
}

// Integrated is driven synchronously by the miner, not by a polling process.
// Its RPC client MUST be an in-process attachment owned by the node lifecycle.
type Integrated struct {
	mu    sync.Mutex
	agent *producerAgent
}

func (p *Integrated) Address() common.Address { return p.agent.address }

func NewIntegrated(client *rpc.Client, chainID *big.Int, address common.Address, cfg Config) (*Integrated, error) {
	if client == nil || chainID == nil || chainID.Sign() <= 0 || address == (common.Address{}) {
		return nil, errors.New("producer: invalid integrated backend")
	}
	if cfg.Lookback == 0 {
		cfg.Lookback = 512
	}
	if cfg.MaxPerSlot == 0 {
		cfg.MaxPerSlot = 4
	}
	if cfg.GasLimit == 0 {
		cfg.GasLimit = 1200000
	}
	if cfg.Lookback > 4096 || cfg.MaxPerSlot < 1 || cfg.MaxPerSlot > 16 || cfg.GasLimit > 3000000 {
		return nil, errors.New("producer: preparation bounds exceeded")
	}
	roots, err := loadCertificates(cfg.EKRoots)
	if err != nil {
		return nil, err
	}
	policy := &tpmregistry.Policy{Version: tpmregistry.EvidenceVersion, RootCertificates: roots, RequireEKCertificateOID: true, MaxEvidenceBytes: 1024 * 1024, AllowedProfileHashes: cfg.ProfileHashes}
	if err = policy.ConfigureCertificateProfile(cfg.CertificateProfile); err != nil {
		return nil, err
	}
	digest, err := policy.Digest()
	if err != nil {
		return nil, err
	}
	key, err := readPrivateKey(cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	chain := ethclient.NewClient(client)
	contract, err := tpmregistry.NewRegistryClient(address, chain)
	if err != nil {
		return nil, err
	}
	return &Integrated{agent: &producerAgent{chainID: new(big.Int).Set(chainID), registry: address, key: key, address: crypto.PubkeyToAddress(key.PublicKey), policy: policy, policyHash: digest, client: chain, rpc: client, contract: contract, lookback: cfg.Lookback, maxPerSlot: cfg.MaxPerSlot, gasLimit: cfg.GasLimit, requests: make(map[common.Hash]*trackedRequest), staged: make(map[string]struct{})}}, nil
}

func (p *Integrated) Prepare(ctx context.Context, parent *types.Header) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if parent == nil || parent.Number == nil {
		return errors.New("producer: missing candidate parent")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.agent.verifyNetwork(ctx); err != nil {
		return err
	}
	head, err := p.agent.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return err
	}
	if head == nil || head.Hash() != parent.Hash() {
		return errors.New("producer: candidate parent changed")
	}
	if err = p.agent.prepareHeader(ctx, parent); err != nil {
		return err
	}
	head, err = p.agent.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return err
	}
	if head == nil || head.Hash() != parent.Hash() {
		return errors.New("producer: candidate parent changed during preparation")
	}
	return ctx.Err()
}
