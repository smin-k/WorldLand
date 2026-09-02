package core

import (
	"math/big"
	"testing"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/core/rawdb"
	"github.com/cryptoecc/WorldLand/core/state"
	"github.com/cryptoecc/WorldLand/params"
)

func TestApplyTPMRegistryFork(t *testing.T) {
	database, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	address := common.HexToAddress("0x801")
	config := &params.ChainConfig{
		TPMRegistryBlock: big.NewInt(5),
		TPMRegistry: &params.TPMRegistryConfig{
			Address: address, FixedCollateral: big.NewInt(100), Governor: common.HexToAddress("0x1001"),
			RegistrationTTL: 90, ActivationDelay: 6,
			Validators: []common.Address{common.HexToAddress("0x2001"), common.HexToAddress("0x2002")},
			Threshold:  2, PolicyDigest: common.HexToHash("0x1234"),
		},
	}
	if err := ApplyTPMRegistryFork(config, big.NewInt(4), database); err != nil {
		t.Fatal(err)
	}
	if len(database.GetCode(address)) != 0 {
		t.Fatal("registry was installed before its migration block")
	}
	if err := ApplyTPMRegistryFork(config, big.NewInt(5), database); err != nil {
		t.Fatal(err)
	}
	if len(database.GetCode(address)) == 0 {
		t.Fatal("registry runtime was not installed at migration block")
	}
}
