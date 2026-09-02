package tpmregistry

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/core/rawdb"
	"github.com/cryptoecc/WorldLand/core/state"
)

func testPredeployConfig() PredeployConfig {
	return PredeployConfig{
		Address: DefaultRegistryAddress, FixedCollateral: big.NewInt(123456),
		Governor: common.HexToAddress("0x1001"), RegistrationTTL: 90,
		ActivationDelay: 6,
		Validators: []common.Address{
			common.HexToAddress("0x2001"), common.HexToAddress("0x2002"), common.HexToAddress("0x2003"),
		},
		Threshold: 2, PolicyDigest: common.HexToHash("0x1234"),
		ProducerSlotCount: 6, ProducerThreshold: 4, ProducerSlotDelay: 2,
		ProducerResponseWindow: 12, ProducerPolicyDigest: common.HexToHash("0x5678"),
	}
}

func TestPredeployStorage(t *testing.T) {
	config := testPredeployConfig()
	storage, err := PredeployStorage(config)
	if err != nil {
		t.Fatal(err)
	}
	if got := storage[common.BigToHash(big.NewInt(2))].Big(); got.Cmp(config.FixedCollateral) != 0 {
		t.Fatalf("collateral %s, want %s", got, config.FixedCollateral)
	}
	packed := storage[common.BigToHash(big.NewInt(5))].Big()
	mask := new(big.Int).SetUint64(^uint64(0))
	if new(big.Int).And(new(big.Int).Set(packed), mask).Uint64() != config.RegistrationTTL {
		t.Fatal("registration TTL was not packed at slot 5 offset 0")
	}
	if new(big.Int).And(new(big.Int).Rsh(new(big.Int).Set(packed), 64), mask).Uint64() != config.ActivationDelay {
		t.Fatal("activation delay was not packed at slot 5 offset 8")
	}
	if new(big.Int).Rsh(new(big.Int).Set(packed), 128).Uint64() != 1 {
		t.Fatal("initial validator epoch was not packed at slot 5 offset 16")
	}
	if storage[solidityMappingSlot(big.NewInt(1), 6)].Big().Uint64() != uint64(config.Threshold) {
		t.Fatal("threshold mapping differs")
	}
	outer := solidityMappingSlot(big.NewInt(1), 9)
	for _, validator := range config.Validators {
		if storage[solidityNestedAddressSlot(validator, outer)].Big().Uint64() != 1 {
			t.Fatalf("validator %s is missing", validator)
		}
	}
	producerConfig := storage[common.BigToHash(big.NewInt(15))].Big()
	if new(big.Int).And(new(big.Int).Set(producerConfig), big.NewInt(0xffff)).Uint64() != uint64(config.ProducerSlotCount) {
		t.Fatal("producer slot count was not packed at slot 15 offset 0")
	}
	if new(big.Int).And(new(big.Int).Rsh(new(big.Int).Set(producerConfig), 16), big.NewInt(0xffff)).Uint64() != uint64(config.ProducerThreshold) {
		t.Fatal("producer threshold was not packed at slot 15 offset 2")
	}
	if storage[common.BigToHash(big.NewInt(16))] != config.ProducerPolicyDigest {
		t.Fatal("producer policy digest differs")
	}
}

func TestPredeployStorageAllowsProducerOnly(t *testing.T) {
	config := testPredeployConfig()
	config.Validators = nil
	config.Threshold = 0
	config.PolicyDigest = common.Hash{}
	storage, err := PredeployStorage(config)
	if err != nil {
		t.Fatal(err)
	}
	packedTiming := storage[common.BigToHash(big.NewInt(5))].Big()
	if new(big.Int).Rsh(new(big.Int).Set(packedTiming), 128).Sign() != 0 {
		t.Fatal("producer-only predeploy unexpectedly enabled a validator epoch")
	}
	if storage[common.BigToHash(big.NewInt(16))] != config.ProducerPolicyDigest {
		t.Fatal("producer-only policy digest differs")
	}
}

func TestAddBootstrapRegistration(t *testing.T) {
	storage, err := PredeployStorage(testPredeployConfig())
	if err != nil {
		t.Fatal(err)
	}
	registration := BootstrapRegistration{
		DID:             common.HexToHash("0xd1d"),
		Controller:      common.HexToAddress("0xc0ffee"),
		WorkKeyHash:     common.HexToHash("0x1111"),
		VRFKeyHash:      common.HexToHash("0x2222"),
		ProfileHash:     common.HexToHash("0x3333"),
		DeviceNullifier: common.HexToHash("0x4444"),
	}
	if err := AddBootstrapRegistration(storage, registration); err != nil {
		t.Fatal(err)
	}
	base := new(big.Int).SetBytes(solidityMappingSlot(registration.DID.Big(), 0).Bytes())
	field := func(offset uint64) common.Hash {
		return common.BigToHash(new(big.Int).Add(new(big.Int).Set(base), new(big.Int).SetUint64(offset)))
	}
	if got := common.BytesToAddress(storage[field(0)].Bytes()[12:]); got != registration.Controller {
		t.Fatalf("controller %s, want %s", got, registration.Controller)
	}
	if storage[field(1)] != registration.WorkKeyHash || storage[field(2)] != registration.VRFKeyHash ||
		storage[field(3)] != registration.ProfileHash || storage[field(4)] != registration.DeviceNullifier ||
		storage[field(5)].Big().Cmp(big.NewInt(1)) != 0 {
		t.Fatal("active registration fields differ")
	}
	if storage[solidityMappingSlot(registration.DeviceNullifier.Big(), 1)].Big().Cmp(big.NewInt(1)) != 0 ||
		storage[solidityMappingSlot(registration.DID.Big(), 12)].Big().Cmp(big.NewInt(1)) != 0 {
		t.Fatal("bootstrap uniqueness indices differ")
	}
	if err := AddBootstrapRegistration(storage, registration); err == nil {
		t.Fatal("duplicate bootstrap registration was accepted")
	}
}

func TestApplyStatePredeploy(t *testing.T) {
	database, err := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	config := testPredeployConfig()
	if err := ApplyStatePredeploy(database, config); err != nil {
		t.Fatal(err)
	}
	code, err := RegistryRuntimeCode()
	if err != nil {
		t.Fatal(err)
	}
	if got := database.GetCode(config.Address); string(got) != string(code) {
		t.Fatal("predeployed runtime differs")
	}
	if err := ApplyStatePredeploy(database, config); err == nil {
		t.Fatal("second state predeploy overwrote existing code")
	}
}

func TestGeneratedStorageLayoutKeepsConsensusSlots(t *testing.T) {
	encoded, err := os.ReadFile("contract/registry.storage.json")
	if err != nil {
		t.Fatal(err)
	}
	var layout struct {
		Storage []struct {
			Label string `json:"label"`
			Slot  string `json:"slot"`
		} `json:"storage"`
	}
	if err := json.Unmarshal(encoded, &layout); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"registrations": "0", "usedNullifiers": "1", "fixedCollateral": "2",
		"governor": "3", "collateralByDID": "4",
	}
	for _, item := range layout.Storage {
		if slot, exists := want[item.Label]; exists {
			if item.Slot != slot {
				t.Fatalf("%s uses slot %s, want %s", item.Label, item.Slot, slot)
			}
			delete(want, item.Label)
		}
	}
	if len(want) != 0 {
		t.Fatalf("storage layout is missing consensus fields: %v", want)
	}
}

func TestRuntimeFitsEIP170(t *testing.T) {
	code, err := RegistryRuntimeCode()
	if err != nil {
		t.Fatal(err)
	}
	if len(code) > 24576 {
		t.Fatalf("registry runtime is %d bytes, exceeds EIP-170", len(code))
	}
}
