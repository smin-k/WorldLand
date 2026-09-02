package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	registrygenesis "github.com/cryptoecc/WorldLand/contracts/tpmregistry/genesis"
	"github.com/cryptoecc/WorldLand/core"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
	"github.com/cryptoecc/WorldLand/params"
)

type metadata struct {
	ChainID          string `json:"chainId"`
	Controller       string `json:"controller"`
	DID              string `json:"did"`
	VRFPublicKey     string `json:"vrfPublicKey"`
	VRFKeyHash       string `json:"vrfKeyHash"`
	TPMWorkPublicKey string `json:"tpmWorkPublicKey"`
	TPMWorkKeyHash   string `json:"tpmWorkKeyHash"`
	ProfileHash      string `json:"profileHash"`
	DeviceNullifier  string `json:"deviceNullifier"`
	RegistryAddress  string `json:"registryAddress"`
	BootstrapScope   string `json:"bootstrapScope"`
}

func main() {
	output := flag.String("out", "", "output genesis JSON")
	metadataOutput := flag.String("metadata", "", "output public metadata JSON")
	privateKeyFile := flag.String("private-key-file", "", "file containing the test miner secp256k1 private key")
	workPublicKeyValue := flag.String("tpm-public-key", "", "uncompressed 65-byte TPM work public key")
	didValue := flag.String("did", "", "optional 32-byte TPM identity")
	chainIDValue := flag.String("chain-id", "103991", "private test-network chain ID")
	timestamp := flag.Uint64("timestamp", 0, "genesis timestamp (default: current Unix time minus one second)")
	flag.Parse()

	if *output == "" || *metadataOutput == "" || *privateKeyFile == "" || *workPublicKeyValue == "" {
		flag.Usage()
		log.Fatal("out, metadata, private-key-file and tpm-public-key are required")
	}
	privateEncoded, err := os.ReadFile(*privateKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	privateKey, err := crypto.HexToECDSA(strings.TrimSpace(string(privateEncoded)))
	if err != nil {
		log.Fatalf("invalid test miner private key: %v", err)
	}
	privateBytes := crypto.FromECDSA(privateKey)
	defer func() {
		for i := range privateBytes {
			privateBytes[i] = 0
		}
	}()
	controller := crypto.PubkeyToAddress(privateKey.PublicKey)
	vrfPublicKey := crypto.CompressPubkey(&privateKey.PublicKey)

	workPublicKey, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(*workPublicKeyValue), "0x"))
	if err != nil {
		log.Fatalf("invalid TPM work public key: %v", err)
	}
	if _, err := tpmwork.ParsePublicKey(workPublicKey); err != nil {
		log.Fatalf("invalid TPM work public key: %v", err)
	}

	chainID, ok := new(big.Int).SetString(*chainIDValue, 10)
	if !ok || chainID.Sign() <= 0 {
		log.Fatalf("invalid chain ID %q", *chainIDValue)
	}
	did := common.Hash{}
	if *didValue != "" {
		value, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(*didValue), "0x"))
		if err != nil || len(value) != common.HashLength {
			log.Fatal("did must be a 32-byte hex value")
		}
		did = common.BytesToHash(value)
	} else {
		did = crypto.Keccak256Hash([]byte("TGPoW two-node bootstrap DID v1"), workPublicKey)
	}
	profileHash := crypto.Keccak256Hash([]byte("TGPoW two-node test profile: Windows TPM 2.0 P-256"))
	deviceNullifier := crypto.Keccak256Hash([]byte("TGPoW two-node test nullifier v1"), workPublicKey)
	workKeyHash := crypto.Keccak256Hash(workPublicKey)
	vrfKeyHash := crypto.Keccak256Hash(vrfPublicKey)

	chainConfig := *params.DaejeonChainConfig
	chainConfig.ChainID = new(big.Int).Set(chainID)
	// Activate VCT and TPM gating together for block one. Keeping genesis at
	// block zero outside VCT makes CalcEligibilityThreshold apply the configured
	// all-eligible bootstrap threshold to the first mined block.
	chainConfig.VCTBlock = big.NewInt(1)
	chainConfig.TPMRegistryBlock = nil
	chainConfig.TPMGatedBlock = big.NewInt(1)
	chainConfig.TPMRegistry = nil
	chainConfig.Vct = &params.VctConfig{
		SeedDelay:                   1,
		MinEligibleBalance:          new(big.Int),
		InitialEligibilityThreshold: big.NewInt(256),
	}
	genesisTimestamp := *timestamp
	if genesisTimestamp == 0 {
		genesisTimestamp = uint64(time.Now().Unix() - 1)
	}
	funding, _ := new(big.Int).SetString("1000000000000000000000000", 10)
	genesis := &core.Genesis{
		Config:     &chainConfig,
		Nonce:      103991,
		Timestamp:  genesisTimestamp,
		ExtraData:  []byte("TGPoW WorldLand two-node E2E"),
		GasLimit:   30_000_000,
		Difficulty: new(big.Int).Set(vctMinimumDifficulty()),
		BaseFee:    new(big.Int).SetUint64(params.InitialBaseFee),
		Alloc: core.GenesisAlloc{
			controller: {Balance: funding},
		},
	}
	policyDigest := crypto.Keccak256Hash([]byte("TGPoW two-node bootstrap validator policy v1"))
	if err := registrygenesis.Apply(genesis, tpmregistry.PredeployConfig{
		Address:         tpmregistry.DefaultRegistryAddress,
		FixedCollateral: new(big.Int),
		Governor:        controller,
		RegistrationTTL: 1000,
		ActivationDelay: 1,
		Validators:      []common.Address{controller},
		Threshold:       1,
		PolicyDigest:    policyDigest,
	}); err != nil {
		log.Fatal(err)
	}
	registryAccount := genesis.Alloc[tpmregistry.DefaultRegistryAddress]
	if err := tpmregistry.AddBootstrapRegistration(registryAccount.Storage, tpmregistry.BootstrapRegistration{
		DID:             did,
		Controller:      controller,
		WorkKeyHash:     workKeyHash,
		VRFKeyHash:      vrfKeyHash,
		ProfileHash:     profileHash,
		DeviceNullifier: deviceNullifier,
	}); err != nil {
		log.Fatal(err)
	}
	genesis.Alloc[tpmregistry.DefaultRegistryAddress] = registryAccount
	if err := genesis.Config.CheckConfigForkOrder(); err != nil {
		log.Fatal(err)
	}
	if err := writeJSON(*output, genesis); err != nil {
		log.Fatal(err)
	}
	publicMetadata := metadata{
		ChainID: chainID.String(), Controller: controller.Hex(), DID: did.Hex(),
		VRFPublicKey: "0x" + hex.EncodeToString(vrfPublicKey), VRFKeyHash: vrfKeyHash.Hex(),
		TPMWorkPublicKey: "0x" + hex.EncodeToString(workPublicKey), TPMWorkKeyHash: workKeyHash.Hex(),
		ProfileHash: profileHash.Hex(), DeviceNullifier: deviceNullifier.Hex(),
		RegistryAddress: tpmregistry.DefaultRegistryAddress.Hex(),
		BootstrapScope:  "The identity is pre-activated only to isolate mining, propagation, and validation; enrollment is tested separately.",
	}
	if err := writeJSON(*metadataOutput, &publicMetadata); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote TGPoW test genesis for controller %s and DID %s\n", controller, did)
}

func vctMinimumDifficulty() *big.Int {
	// Keep the production consensus floor. The E2E harness waits for genuine
	// TPM-gated work and does not weaken block validity for a faster demo.
	return big.NewInt(65_536)
}

func writeJSON(path string, value interface{}) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(encoded, '\n'), 0o600)
}
