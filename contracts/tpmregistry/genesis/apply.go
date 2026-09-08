package genesis

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/core"
)

// Apply adds the registry runtime and initialized storage to a new chain. It
// refuses to overwrite an existing allocation at the configured address.
func Apply(spec *core.Genesis, config tpmregistry.PredeployConfig) error {
	if spec == nil {
		return errors.New("tpmregistry: nil genesis")
	}
	if err := spec.Config.CheckTPMActivationDelay(config.ActivationDelay); err != nil {
		return err
	}
	address := config.Address
	if address == (common.Address{}) {
		address = tpmregistry.DefaultRegistryAddress
		config.Address = address
	}
	if account, exists := spec.Alloc[address]; exists && (len(account.Code) != 0 || len(account.Storage) != 0 || account.Nonce != 0 || (account.Balance != nil && account.Balance.Sign() != 0)) {
		return fmt.Errorf("tpmregistry: genesis allocation %s already exists", address)
	}
	code, err := tpmregistry.RegistryRuntimeCode()
	if err != nil {
		return err
	}
	storage, err := tpmregistry.PredeployStorage(config)
	if err != nil {
		return err
	}
	if spec.Alloc == nil {
		spec.Alloc = make(core.GenesisAlloc)
	}
	spec.Alloc[address] = core.GenesisAccount{Code: code, Storage: storage, Balance: new(big.Int)}
	return nil
}
