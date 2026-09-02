package params

import (
	"math/big"
	"testing"

	"github.com/cryptoecc/WorldLand/common"
)

func registryForkConfig() *ChainConfig {
	return &ChainConfig{
		ChainID: big.NewInt(103), HomesteadBlock: big.NewInt(0), EIP150Block: big.NewInt(0),
		EIP155Block: big.NewInt(0), EIP158Block: big.NewInt(0), ByzantiumBlock: big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0), PetersburgBlock: big.NewInt(0), IstanbulBlock: big.NewInt(0),
		BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0), VCTBlock: big.NewInt(10),
		TPMRegistryBlock: big.NewInt(20), TPMGatedBlock: big.NewInt(30),
		TPMRegistry: &TPMRegistryConfig{
			Address: common.HexToAddress("0x801"), FixedCollateral: big.NewInt(100),
			Governor: common.HexToAddress("0x1001"), RegistrationTTL: 90, ActivationDelay: 6,
			Validators: []common.Address{common.HexToAddress("0x2001"), common.HexToAddress("0x2002")},
			Threshold:  2, PolicyDigest: common.HexToHash("0x1234"),
			ProducerSlotCount: 6, ProducerThreshold: 4, ProducerSlotDelay: 2,
			ProducerResponseWindow: 12, ProducerPolicyDigest: common.HexToHash("0x5678"),
		},
	}
}

func TestTPMRegistryForkOrdering(t *testing.T) {
	config := registryForkConfig()
	if err := config.CheckConfigForkOrder(); err != nil {
		t.Fatal(err)
	}
	config.TPMRegistryBlock = new(big.Int).Set(config.TPMGatedBlock)
	if err := config.CheckConfigForkOrder(); err == nil {
		t.Fatal("registry migration at TPM activation was accepted")
	}
	config = registryForkConfig()
	config.TPMRegistry = nil
	if err := config.CheckConfigForkOrder(); err == nil {
		t.Fatal("registry block without migration configuration was accepted")
	}
}

func TestTPMRegistryConfigCompatibility(t *testing.T) {
	stored := registryForkConfig()
	updated := registryForkConfig()
	updated.TPMRegistry.Threshold = 1
	if err := stored.CheckCompatible(updated, 19); err != nil {
		t.Fatalf("future migration configuration rejected: %v", err)
	}
	if err := stored.CheckCompatible(updated, 20); err == nil {
		t.Fatal("past migration configuration change was accepted")
	}
}

func TestTPMRegistryConfigValidation(t *testing.T) {
	producerOnly := registryForkConfig()
	producerOnly.TPMRegistry.Validators = nil
	producerOnly.TPMRegistry.Threshold = 0
	producerOnly.TPMRegistry.PolicyDigest = common.Hash{}
	if err := producerOnly.CheckConfigForkOrder(); err != nil {
		t.Fatalf("producer-only registry rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*TPMRegistryConfig)
	}{
		{"negative collateral", func(c *TPMRegistryConfig) { c.FixedCollateral = big.NewInt(-1) }},
		{"missing governor", func(c *TPMRegistryConfig) { c.Governor = common.Address{} }},
		{"missing ttl", func(c *TPMRegistryConfig) { c.RegistrationTTL = 0 }},
		{"missing policy", func(c *TPMRegistryConfig) { c.PolicyDigest = common.Hash{} }},
		{"zero threshold", func(c *TPMRegistryConfig) { c.Threshold = 0 }},
		{"threshold above validator count", func(c *TPMRegistryConfig) { c.Threshold = 3 }},
		{"zero validator", func(c *TPMRegistryConfig) { c.Validators[0] = common.Address{} }},
		{"duplicate validator", func(c *TPMRegistryConfig) { c.Validators[1] = c.Validators[0] }},
		{"producer threshold above slots", func(c *TPMRegistryConfig) { c.ProducerThreshold = 7 }},
		{"missing producer response window", func(c *TPMRegistryConfig) { c.ProducerResponseWindow = 0 }},
		{"missing producer policy", func(c *TPMRegistryConfig) { c.ProducerPolicyDigest = common.Hash{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := registryForkConfig()
			test.mutate(config.TPMRegistry)
			if err := config.CheckConfigForkOrder(); err == nil {
				t.Fatal("invalid TPM registry configuration was accepted")
			}
		})
	}
}
