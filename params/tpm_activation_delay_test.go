package params

import (
	"math/big"
	"testing"
)

func TestTPMActivationDelayMustCoverSeedDelay(t *testing.T) {
	for _, seedDelay := range []uint64{0, 1, 2, 6} {
		config := registryForkConfig()
		config.Vct = &VctConfig{SeedDelay: seedDelay}
		minimum := config.Vct.EffectiveSeedDelay()
		config.TPMRegistry.ActivationDelay = minimum - 1
		if err := config.CheckConfigForkOrder(); err == nil {
			t.Errorf("seed delay %d accepted insufficient activation delay %d", seedDelay, minimum-1)
		}
		for _, delay := range []uint64{minimum, minimum + 1} {
			config.TPMRegistry.ActivationDelay = delay
			if err := config.CheckConfigForkOrder(); err != nil {
				t.Errorf("seed delay %d rejected activation delay %d: %v", seedDelay, delay, err)
			}
		}
	}
	config := registryForkConfig()
	config.Vct = nil
	config.TPMRegistry.ActivationDelay = 0
	if err := config.CheckConfigForkOrder(); err == nil {
		t.Fatal("omitted VCT config must retain legacy one-block seed delay")
	}
	config.TPMGatedBlock = nil
	if err := config.CheckConfigForkOrder(); err != nil {
		t.Fatalf("registry-only chain was subjected to a TPM consensus seed: %v", err)
	}
}

func TestTPMActivationDelayCompatibilityIsUnchanged(t *testing.T) {
	stored, updated := registryForkConfig(), registryForkConfig()
	stored.Vct, updated.Vct = &VctConfig{SeedDelay: 2}, &VctConfig{SeedDelay: 2}
	updated.TPMRegistry.ActivationDelay = 7
	if err := updated.CheckConfigForkOrder(); err != nil {
		t.Fatal(err)
	}
	if err := stored.CheckCompatible(updated, 19); err != nil {
		t.Fatalf("future registry delay change rejected: %v", err)
	}
	if err := stored.CheckCompatible(updated, 20); err == nil || err.What != "TPM registry configuration" {
		t.Fatalf("deployed registry delay change was not rejected: %v", err)
	}
	updated = registryForkConfig()
	updated.Vct = &VctConfig{SeedDelay: 3}
	if err := stored.CheckCompatible(updated, 10); err == nil || err.What != "VCT seed delay" {
		t.Fatalf("active consensus seed change was not rejected: %v", err)
	}
	for _, public := range []*ChainConfig{MainnetChainConfig, SeoulChainConfig, GwangjuChainConfig, DaejeonChainConfig} {
		if public.TPMGatedBlock != nil {
			t.Fatal("test requires an existing public chain without TPM consensus")
		}
		if err := public.CheckTPMActivationDelay(0); err != nil {
			t.Fatalf("public chain %s affected: %v", public.ChainID, err)
		}
	}
	// TPM may be enabled at genesis or at a future fork: both need a safe
	// registration delay before allowing the configuration to be installed.
	if err := (&ChainConfig{TPMGatedBlock: big.NewInt(0)}).CheckTPMActivationDelay(0); err == nil {
		t.Fatal("genesis-active TPM chain accepted zero delay")
	}
}
