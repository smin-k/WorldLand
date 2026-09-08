package genesis

import (
	"math/big"
	"testing"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/core"
	"github.com/cryptoecc/WorldLand/params"
)

func TestApply(t *testing.T) {
	address := tpmregistry.DefaultRegistryAddress
	config := tpmregistry.PredeployConfig{
		Address: address, FixedCollateral: big.NewInt(100), Governor: common.HexToAddress("0x1001"),
		RegistrationTTL: 90, ActivationDelay: 6,
		Validators: []common.Address{common.HexToAddress("0x2001"), common.HexToAddress("0x2002")},
		Threshold:  2, PolicyDigest: common.HexToHash("0x1234"),
	}
	spec := &core.Genesis{}
	if err := Apply(spec, config); err != nil {
		t.Fatal(err)
	}
	account, exists := spec.Alloc[address]
	if !exists || len(account.Code) == 0 || len(account.Storage) == 0 {
		t.Fatal("registry code and storage were not added to genesis")
	}
	if err := Apply(spec, config); err == nil {
		t.Fatal("existing registry allocation was overwritten")
	}
}

func TestApplyChecksActivationBeforeChangingGenesis(t *testing.T) {
	config := tpmregistry.PredeployConfig{
		Address: tpmregistry.DefaultRegistryAddress, FixedCollateral: big.NewInt(100),
		Governor: common.HexToAddress("0x1001"), RegistrationTTL: 90, ActivationDelay: 1,
		Validators: []common.Address{common.HexToAddress("0x2001")},
		Threshold:  1, PolicyDigest: common.HexToHash("0x1234"),
	}
	spec := &core.Genesis{Config: &params.ChainConfig{
		VCTBlock: big.NewInt(0), TPMGatedBlock: big.NewInt(0), Vct: &params.VctConfig{SeedDelay: 2},
	}}
	if err := Apply(spec, config); err == nil {
		t.Fatal("genesis predeploy accepted activation delay shorter than seed delay")
	}
	if spec.Alloc != nil {
		t.Fatal("rejected predeploy mutated the genesis allocation")
	}
	config.ActivationDelay = 2
	if err := Apply(spec, config); err != nil {
		t.Fatalf("activation delay equal to seed delay rejected: %v", err)
	}
}
