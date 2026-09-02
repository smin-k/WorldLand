package core

import (
	"fmt"
	"math/big"

	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/core/state"
	"github.com/cryptoecc/WorldLand/params"
)

// ApplyTPMRegistryFork installs the registry at its configured one-time state
// transition. It is called by block import, local block production and chain
// generation so all paths compute the same state root.
func ApplyTPMRegistryFork(config *params.ChainConfig, blockNumber *big.Int, database *state.StateDB) error {
	if config == nil || config.TPMRegistryBlock == nil || config.TPMRegistryBlock.Cmp(blockNumber) != 0 {
		return nil
	}
	registryConfig := config.TPMRegistry
	if registryConfig == nil {
		return fmt.Errorf("TPM registry migration block has no configuration")
	}
	if err := tpmregistry.ApplyStatePredeploy(database, tpmregistry.PredeployConfig{
		Address: registryConfig.Address, FixedCollateral: registryConfig.FixedCollateral,
		Governor: registryConfig.Governor, RegistrationTTL: registryConfig.RegistrationTTL,
		ActivationDelay: registryConfig.ActivationDelay, Validators: registryConfig.Validators,
		Threshold: registryConfig.Threshold, PolicyDigest: registryConfig.PolicyDigest,
		ProducerSlotCount:      registryConfig.ProducerSlotCount,
		ProducerThreshold:      registryConfig.ProducerThreshold,
		ProducerSlotDelay:      registryConfig.ProducerSlotDelay,
		ProducerResponseWindow: registryConfig.ProducerResponseWindow,
		ProducerPolicyDigest:   registryConfig.ProducerPolicyDigest,
	}); err != nil {
		return fmt.Errorf("apply TPM registry migration: %w", err)
	}
	return nil
}
