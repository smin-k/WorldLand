package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	registrygenesis "github.com/cryptoecc/WorldLand/contracts/tpmregistry/genesis"
	"github.com/cryptoecc/WorldLand/core"
)

type repeatedFlag []string

func (values *repeatedFlag) String() string { return strings.Join(*values, ",") }
func (values *repeatedFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	var validatorValues repeatedFlag
	input := flag.String("in", "", "input genesis JSON")
	output := flag.String("out", "", "new output genesis JSON")
	addressValue := flag.String("address", tpmregistry.DefaultRegistryAddress.Hex(), "registry predeploy address")
	governorValue := flag.String("governor", "", "registry governor address")
	collateralValue := flag.String("collateral", "0", "fixed collateral in wei")
	ttl := flag.Uint64("registration-ttl", 0, "registration lifetime in blocks")
	activationDelay := flag.Uint64("activation-delay", 0, "activation delay in blocks")
	threshold := flag.Uint("threshold", 0, "validator approval threshold")
	policyValue := flag.String("policy-digest", "", "validator policy digest")
	producerSlots := flag.Uint("producer-slots", 0, "dynamic producer committee slot count (0 disables)")
	producerThreshold := flag.Uint("producer-threshold", 0, "required approved producer slots")
	producerSlotDelay := flag.Uint("producer-slot-delay", 0, "blocks between request inclusion and first producer slot")
	producerResponseWindow := flag.Uint("producer-response-window", 0, "blocks after the last slot for responses and approvals")
	producerPolicyValue := flag.String("producer-policy-digest", "", "dynamic producer evidence policy digest")
	flag.Var(&validatorValues, "validator", "validator address (repeatable)")
	flag.Parse()

	legacyConfigured := len(validatorValues) != 0 || *threshold != 0 || *policyValue != ""
	producerConfigured := *producerSlots != 0 || *producerThreshold != 0 || *producerSlotDelay != 0 ||
		*producerResponseWindow != 0 || *producerPolicyValue != ""
	if *input == "" || *output == "" || !common.IsHexAddress(*addressValue) ||
		!common.IsHexAddress(*governorValue) || *ttl == 0 || (!legacyConfigured && !producerConfigured) {
		flag.Usage()
		log.Fatal("in, out, governor, registration-ttl and at least one enrollment mode are required")
	}
	if legacyConfigured && (*threshold == 0 || len(validatorValues) == 0 || len(strings.TrimPrefix(*policyValue, "0x")) != 64) {
		log.Fatal("threshold, policy-digest and validators must be supplied together")
	}
	inputAbsolute, err := filepath.Abs(*input)
	if err != nil {
		log.Fatal(err)
	}
	outputAbsolute, err := filepath.Abs(*output)
	if err != nil {
		log.Fatal(err)
	}
	if strings.EqualFold(inputAbsolute, outputAbsolute) {
		log.Fatal("refusing to overwrite input genesis; choose a different out path")
	}
	encoded, err := os.ReadFile(inputAbsolute)
	if err != nil {
		log.Fatal(err)
	}
	var genesis core.Genesis
	if err := json.Unmarshal(encoded, &genesis); err != nil {
		log.Fatal(err)
	}
	collateral, ok := new(big.Int).SetString(*collateralValue, 10)
	if !ok {
		log.Fatalf("invalid collateral %q", *collateralValue)
	}
	validators := make([]common.Address, len(validatorValues))
	for i, value := range validatorValues {
		if !common.IsHexAddress(value) {
			log.Fatalf("invalid validator address %q", value)
		}
		validators[i] = common.HexToAddress(value)
	}
	if *threshold > uint(len(validators)) || *threshold > uint(^uint16(0)) {
		log.Fatal("threshold exceeds validator count")
	}
	if *producerSlots > uint(^uint16(0)) || *producerThreshold > *producerSlots ||
		*producerThreshold > uint(^uint16(0)) || *producerSlotDelay > uint(^uint32(0)) ||
		*producerResponseWindow > uint(^uint32(0)) {
		log.Fatal("invalid dynamic producer committee parameters")
	}
	if producerConfigured && (*producerSlots == 0 || *producerThreshold == 0 || *producerResponseWindow == 0 || len(strings.TrimPrefix(*producerPolicyValue, "0x")) != 64) {
		log.Fatal("producer-threshold, producer-response-window and producer-policy-digest are required when producer-slots is enabled")
	}
	config := tpmregistry.PredeployConfig{
		Address: common.HexToAddress(*addressValue), FixedCollateral: collateral,
		Governor: common.HexToAddress(*governorValue), RegistrationTTL: *ttl,
		ActivationDelay: *activationDelay, Validators: validators,
		Threshold: uint16(*threshold), PolicyDigest: common.HexToHash(*policyValue),
		ProducerSlotCount: uint16(*producerSlots), ProducerThreshold: uint16(*producerThreshold),
		ProducerSlotDelay: uint32(*producerSlotDelay), ProducerResponseWindow: uint32(*producerResponseWindow),
		ProducerPolicyDigest: common.HexToHash(*producerPolicyValue),
	}
	if err := registrygenesis.Apply(&genesis, config); err != nil {
		log.Fatal(err)
	}
	outputJSON, err := json.MarshalIndent(&genesis, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	outputJSON = append(outputJSON, '\n')
	if err := os.WriteFile(outputAbsolute, outputJSON, 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote TPM registry predeploy at %s to %s\n", config.Address, outputAbsolute)
}
