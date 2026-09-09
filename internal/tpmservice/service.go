// Package tpmservice owns integrated enrollment and producer preparation for a node.
package tpmservice

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cryptoecc/WorldLand/accounts"
	"github.com/cryptoecc/WorldLand/accounts/keystore"
	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/eth"
	"github.com/cryptoecc/WorldLand/ethclient"
	"github.com/cryptoecc/WorldLand/internal/tpmenroll"
	"github.com/cryptoecc/WorldLand/internal/tpmproducer"
	"github.com/cryptoecc/WorldLand/log"
	"github.com/cryptoecc/WorldLand/rpc"
)

// Config is an opt-in local JSON file. Paths point to local files; no RPC URL is accepted.
type Config struct {
	Producer                  tpmproducer.Config
	Enrollment                tpmenroll.Config
	Enroll                    bool
	PreparationTimeoutSeconds int
}

type Service struct {
	cfg     Config
	backend *eth.Ethereum
	rpc     *rpc.Client
	mine    bool
	threads int
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func New(cfg Config, backend *eth.Ethereum, client *rpc.Client, mine bool, threads int) (*Service, error) {
	if backend == nil || client == nil {
		return nil, errors.New("TPM integration requires a full node")
	}
	if cfg.PreparationTimeoutSeconds == 0 {
		cfg.PreparationTimeoutSeconds = 5
	}
	if cfg.PreparationTimeoutSeconds < 1 || cfg.PreparationTimeoutSeconds > 30 {
		return nil, errors.New("TPM preparation timeout must be 1..30 seconds")
	}
	chain := backend.BlockChain().Config()
	if chain.TPMGatedBlock == nil {
		return nil, errors.New("TPM integration requires a TPM-gated chain")
	}
	address := tpmregistry.DefaultRegistryAddress
	if chain.TPMRegistry != nil && chain.TPMRegistry.Address != (common.Address{}) {
		address = chain.TPMRegistry.Address
	}
	producer, err := tpmproducer.NewIntegrated(client, chain.ChainID, address, cfg.Producer)
	if err != nil {
		return nil, err
	}
	coinbase, err := backend.Etherbase()
	if err != nil || coinbase != producer.Address() {
		return nil, errors.New("TPM producer key must match local mining coinbase")
	}
	if cfg.Enroll && (cfg.Enrollment.Identity == (common.Hash{}) || cfg.Enrollment.WorkKey == "" || cfg.Enrollment.AttestationKey == "" || cfg.Enrollment.VRFPublicKey == "" || cfg.Enrollment.Profile == "") {
		return nil, errors.New("integrated enrollment requires identity, work/attestation key, VRF public key and profile")
	}
	if err = backend.Miner().SetEnrollmentPreparer(producer, time.Duration(cfg.PreparationTimeoutSeconds)*time.Second); err != nil {
		return nil, err
	}
	cfg.Enrollment.ControllerKey = cfg.Producer.KeyFile
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{cfg: cfg, backend: backend, rpc: client, mine: mine, threads: threads, ctx: ctx, cancel: cancel}, nil
}

func (s *Service) Start() error {
	if !s.cfg.Enroll && !s.mine {
		return nil
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.run(); err != nil && s.ctx.Err() == nil {
			log.Error("Integrated TPM service stopped; mining not automatically retried", "err", err)
		}
	}()
	return nil
}

func (s *Service) run() error {
	if s.cfg.Enroll {
		chain := s.backend.BlockChain().Config()
		address := tpmregistry.DefaultRegistryAddress
		if chain.TPMRegistry != nil && chain.TPMRegistry.Address != (common.Address{}) {
			address = chain.TPMRegistry.Address
		}
		log.Info("Integrated TPM enrollment starting")
		if err := tpmenroll.RunIntegrated(s.ctx, ethclient.NewClient(s.rpc), chain.ChainID, address, s.cfg.Enrollment); err != nil {
			return err
		}
		log.Info("Integrated TPM identity activated")
	}
	if !s.mine {
		return nil
	}
	// Node lifecycle Start precedes the CLI's account-unlock step. Never race that
	// step and silently start VCT without the unlocked VRF key.
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		addr, err := s.backend.Etherbase()
		if err == nil {
			for _, store := range s.backend.AccountManager().Backends(keystore.KeyStoreType) {
				if _, err := store.(*keystore.KeyStore).GetUnlockedKey(accounts.Account{Address: addr}); err == nil {
					if err = ctx.Err(); err != nil {
						return err
					}
					return s.backend.StartMining(s.threads)
				}
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("TPM mining requires an unlocked local coinbase account")
		case <-ticker.C:
		}
	}
}

func (s *Service) Stop() error { s.cancel(); s.wg.Wait(); s.rpc.Close(); return nil }
