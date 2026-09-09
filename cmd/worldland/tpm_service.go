package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/cryptoecc/WorldLand/cmd/utils"
	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/common/hexutil"
	"github.com/cryptoecc/WorldLand/eth"
	"github.com/cryptoecc/WorldLand/eth/ethconfig"
	"github.com/cryptoecc/WorldLand/internal/tpmservice"
	"github.com/cryptoecc/WorldLand/node"
	"github.com/urfave/cli/v2"
)

var tpmServiceFlag = &cli.StringFlag{Name: "tpm.integrated", Usage: "Local JSON configuration for in-process TPM registration and synchronous block preparation"}

func registerTPMService(ctx *cli.Context, stack *node.Node, backend *eth.Ethereum, ethCfg *ethconfig.Config) error {
	path := ctx.String(tpmServiceFlag.Name)
	if path == "" {
		return nil
	}
	if backend == nil {
		return fmt.Errorf("--tpm.integrated requires a full node")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var cfg tpmservice.Config
	decoder := json.NewDecoder(io.LimitReader(f, 64*1024))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&cfg); err != nil {
		return err
	}
	var extra interface{}
	if err = decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("invalid trailing TPM configuration")
	}
	cfg.Enrollment.WorkKey = ethCfg.Miner.TPMKeyName
	cfg.Enrollment.CreateKeys = ethCfg.Miner.TPMCreate
	raw, err := hexutil.Decode(ethCfg.Miner.TPMDID)
	if err != nil || len(raw) != 32 || cfg.Enrollment.WorkKey == "" {
		return fmt.Errorf("--tpm.integrated requires miner.tpmkey and miner.tpmdid")
	}
	cfg.Enrollment.Identity = common.BytesToHash(raw)
	client, err := stack.Attach()
	if err != nil {
		return err
	}
	service, err := tpmservice.New(cfg, backend, client, ctx.Bool(utils.MiningEnabledFlag.Name), ctx.Int(utils.MinerThreadsFlag.Name))
	if err != nil {
		client.Close()
		return err
	}
	stack.RegisterLifecycle(service)
	return nil
}
