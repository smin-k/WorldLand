package tpmregistry

import (
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/core/state"
	"github.com/cryptoecc/WorldLand/crypto"
)

var DefaultRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000000000801")

//go:embed contract/registry.runtime.hex
var registryRuntimeHex string

type PredeployConfig struct {
	Address                common.Address
	FixedCollateral        *big.Int
	Governor               common.Address
	RegistrationTTL        uint64
	ActivationDelay        uint64
	Validators             []common.Address
	Threshold              uint16
	PolicyDigest           common.Hash
	ProducerSlotCount      uint16
	ProducerThreshold      uint16
	ProducerSlotDelay      uint32
	ProducerResponseWindow uint32
	ProducerPolicyDigest   common.Hash
}

// BootstrapRegistration describes an identity that is already active in a
// private-network genesis. It is intentionally separate from PredeployConfig:
// production networks must use the on-chain enrollment state machine, whereas
// end-to-end test networks can isolate the mining and validation path without
// first running an attestation committee.
type BootstrapRegistration struct {
	DID             common.Hash
	Controller      common.Address
	WorkKeyHash     common.Hash
	VRFKeyHash      common.Hash
	ProfileHash     common.Hash
	DeviceNullifier common.Hash
}

func RegistryRuntimeCode() ([]byte, error) {
	code, err := hex.DecodeString(strings.TrimSpace(registryRuntimeHex))
	if err != nil {
		return nil, fmt.Errorf("tpmregistry: decode embedded runtime: %w", err)
	}
	if len(code) == 0 {
		return nil, errors.New("tpmregistry: embedded runtime is empty")
	}
	return code, nil
}

// PredeployStorage constructs the registry's initial state. Legacy validators
// and the dynamic producer committee can be enabled independently.
func PredeployStorage(config PredeployConfig) (map[common.Hash]common.Hash, error) {
	if err := validatePredeployConfig(&config); err != nil {
		return nil, err
	}
	storage := make(map[common.Hash]common.Hash)
	storage[common.BigToHash(big.NewInt(2))] = common.BigToHash(config.FixedCollateral)
	storage[common.BigToHash(big.NewInt(3))] = common.BytesToHash(config.Governor[:])
	packedTiming := new(big.Int).SetUint64(config.RegistrationTTL)
	packedTiming.Or(packedTiming, new(big.Int).Lsh(new(big.Int).SetUint64(config.ActivationDelay), 64))
	legacyConfigured := len(config.Validators) != 0
	if legacyConfigured {
		packedTiming.Or(packedTiming, new(big.Int).Lsh(big.NewInt(1), 128)) // currentValidatorEpoch
	}
	storage[common.BigToHash(big.NewInt(5))] = common.BigToHash(packedTiming)

	if legacyConfigured {
		epoch := big.NewInt(1)
		storage[solidityMappingSlot(epoch, 6)] = common.BigToHash(new(big.Int).SetUint64(uint64(config.Threshold)))
		storage[solidityMappingSlot(epoch, 7)] = common.BigToHash(new(big.Int).SetUint64(uint64(len(config.Validators))))
		storage[solidityMappingSlot(epoch, 8)] = config.PolicyDigest
		validatorMap := solidityMappingSlot(epoch, 9)
		for _, validator := range config.Validators {
			storage[solidityNestedAddressSlot(validator, validatorMap)] = common.BigToHash(big.NewInt(1))
		}
	}
	if config.ProducerSlotCount != 0 {
		packedProducerConfig := new(big.Int).SetUint64(uint64(config.ProducerSlotCount))
		packedProducerConfig.Or(packedProducerConfig, new(big.Int).Lsh(new(big.Int).SetUint64(uint64(config.ProducerThreshold)), 16))
		packedProducerConfig.Or(packedProducerConfig, new(big.Int).Lsh(new(big.Int).SetUint64(uint64(config.ProducerSlotDelay)), 32))
		packedProducerConfig.Or(packedProducerConfig, new(big.Int).Lsh(new(big.Int).SetUint64(uint64(config.ProducerResponseWindow)), 64))
		storage[common.BigToHash(big.NewInt(15))] = common.BigToHash(packedProducerConfig)
		storage[common.BigToHash(big.NewInt(16))] = config.ProducerPolicyDigest
	}
	return storage, nil
}

// AddBootstrapRegistration inserts one already-active identity into registry
// genesis storage. The layout is checked by TestGeneratedStorageLayoutKeepsConsensusSlots
// and mirrors the Registration struct read by the VCT consensus engine.
func AddBootstrapRegistration(storage map[common.Hash]common.Hash, registration BootstrapRegistration) error {
	if storage == nil {
		return errors.New("tpmregistry: nil bootstrap storage")
	}
	if registration.DID == (common.Hash{}) || registration.Controller == (common.Address{}) ||
		registration.WorkKeyHash == (common.Hash{}) || registration.VRFKeyHash == (common.Hash{}) ||
		registration.ProfileHash == (common.Hash{}) || registration.DeviceNullifier == (common.Hash{}) {
		return errors.New("tpmregistry: incomplete bootstrap registration")
	}
	base := new(big.Int).SetBytes(solidityMappingSlot(registration.DID.Big(), 0).Bytes())
	fieldSlot := func(offset uint64) common.Hash {
		return common.BigToHash(new(big.Int).Add(new(big.Int).Set(base), new(big.Int).SetUint64(offset)))
	}
	if storage[fieldSlot(5)] != (common.Hash{}) || storage[solidityMappingSlot(registration.DID.Big(), 12)] != (common.Hash{}) {
		return fmt.Errorf("tpmregistry: bootstrap DID %s already registered", registration.DID)
	}
	if storage[solidityMappingSlot(registration.DeviceNullifier.Big(), 1)] != (common.Hash{}) {
		return fmt.Errorf("tpmregistry: bootstrap nullifier %s already used", registration.DeviceNullifier)
	}
	storage[fieldSlot(0)] = common.BytesToHash(registration.Controller[:])
	storage[fieldSlot(1)] = registration.WorkKeyHash
	storage[fieldSlot(2)] = registration.VRFKeyHash
	storage[fieldSlot(3)] = registration.ProfileHash
	storage[fieldSlot(4)] = registration.DeviceNullifier
	storage[fieldSlot(5)] = common.BigToHash(big.NewInt(1))
	storage[solidityMappingSlot(registration.DeviceNullifier.Big(), 1)] = common.BigToHash(big.NewInt(1))
	storage[solidityMappingSlot(registration.DID.Big(), 12)] = common.BigToHash(big.NewInt(1))
	return nil
}

// ApplyStatePredeploy performs the same initialization in a consensus hard-fork
// state transition. The caller must invoke it at one uniquely configured block.
func ApplyStatePredeploy(database *state.StateDB, config PredeployConfig) error {
	if database == nil {
		return errors.New("tpmregistry: nil state database")
	}
	address := config.Address
	if address == (common.Address{}) {
		address = DefaultRegistryAddress
		config.Address = address
	}
	if len(database.GetCode(address)) != 0 {
		return fmt.Errorf("tpmregistry: state account %s already has code", address)
	}
	code, err := RegistryRuntimeCode()
	if err != nil {
		return err
	}
	storage, err := PredeployStorage(config)
	if err != nil {
		return err
	}
	database.SetCode(address, code)
	for slot, value := range storage {
		database.SetState(address, slot, value)
	}
	return nil
}

func validatePredeployConfig(config *PredeployConfig) error {
	if config.FixedCollateral == nil || config.FixedCollateral.Sign() < 0 || config.FixedCollateral.BitLen() > 256 {
		return errors.New("tpmregistry: invalid fixed collateral")
	}
	if config.Governor == (common.Address{}) || config.RegistrationTTL == 0 {
		return errors.New("tpmregistry: governor and registration TTL are required")
	}
	legacyConfigured := len(config.Validators) != 0 || config.Threshold != 0 || config.PolicyDigest != (common.Hash{})
	if legacyConfigured && (len(config.Validators) == 0 || len(config.Validators) > int(^uint16(0)) ||
		config.Threshold == 0 || int(config.Threshold) > len(config.Validators) || config.PolicyDigest == (common.Hash{})) {
		return errors.New("tpmregistry: invalid validator threshold")
	}
	seen := make(map[common.Address]struct{}, len(config.Validators))
	for _, validator := range config.Validators {
		if validator == (common.Address{}) {
			return errors.New("tpmregistry: zero validator")
		}
		if _, exists := seen[validator]; exists {
			return errors.New("tpmregistry: duplicate validator")
		}
		seen[validator] = struct{}{}
	}
	producerConfigured := config.ProducerSlotCount != 0 || config.ProducerThreshold != 0 ||
		config.ProducerSlotDelay != 0 || config.ProducerResponseWindow != 0 ||
		config.ProducerPolicyDigest != (common.Hash{})
	if producerConfigured {
		if config.ProducerSlotCount == 0 || config.ProducerThreshold == 0 ||
			config.ProducerThreshold > config.ProducerSlotCount || config.ProducerResponseWindow == 0 ||
			config.ProducerPolicyDigest == (common.Hash{}) {
			return errors.New("tpmregistry: invalid producer committee")
		}
	}
	if !legacyConfigured && !producerConfigured {
		return errors.New("tpmregistry: no enrollment mode configured")
	}
	return nil
}

func solidityMappingSlot(key *big.Int, slot uint64) common.Hash {
	return crypto.Keccak256Hash(encodeWords(key.Bytes(), new(big.Int).SetUint64(slot).Bytes()))
}

func solidityNestedAddressSlot(address common.Address, outerSlot common.Hash) common.Hash {
	return crypto.Keccak256Hash(encodeWords(address[:], outerSlot[:]))
}
