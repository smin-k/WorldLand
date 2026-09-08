// setup prepares disposable node identities and a two-bootstrap-node genesis.
package main

import (
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	registrygenesis "github.com/cryptoecc/WorldLand/contracts/tpmregistry/genesis"
	"github.com/cryptoecc/WorldLand/core"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/params"
)

const chainID = 103993
const profile = "WorldLand GCP CAS v1 demo: RSA2048 EK/AK; P256 TPM work; secp256k1 VRF"

type nodeIdentity struct {
	Controller common.Address       `json:"controller"`
	DID        common.Hash          `json:"did"`
	Evidence   tpmregistry.Evidence `json:"evidence"`
}

func policy() *tpmregistry.Policy {
	p := &tpmregistry.Policy{Version: 1, MaxEvidenceBytes: 1024 * 1024, AllowedProfileHashes: []common.Hash{crypto.Keccak256Hash([]byte(profile))}}
	must(p.ConfigureCertificateProfile(tpmregistry.CertificateProfileGCPCAS))
	return p
}

func main() {
	if len(os.Args) < 3 {
		log.Fatal("usage: setup prepare DIRECTORY | genesis DIRECTORY identity1.json ... identity5.json")
	}
	dir := os.Args[2]
	switch os.Args[1] {
	case "prepare":
		prepare(dir)
	case "genesis":
		genesis(dir, os.Args[3:])
	default:
		log.Fatal("unknown action")
	}
}

func prepare(dir string) {
	raw, err := os.ReadFile(filepath.Join(dir, "preflight.json"))
	must(err)
	var probe struct {
		Success                    bool
		ActivateCredentialVerified bool
		CertifyVerified            bool
		EnrollmentIdentity         tpmregistry.Evidence
		WorkPublicKey              string
	}
	must(json.Unmarshal(raw, &probe))
	if !probe.Success || !probe.ActivateCredentialVerified || !probe.CertifyVerified {
		log.Fatal("live TPM preflight not successful")
	}
	keyPath := filepath.Join(dir, "account.key")
	key, err := crypto.LoadECDSA(keyPath)
	if os.IsNotExist(err) {
		key, err = crypto.GenerateKey()
		must(err)
		must(writeNew(keyPath, []byte(hex.EncodeToString(crypto.FromECDSA(key)))))
	} else {
		must(err)
	}
	evidence := probe.EnrollmentIdentity
	evidence.Version = 1
	evidence.WorkPublicKey, err = hex.DecodeString(probe.WorkPublicKey)
	must(err)
	evidence.VRFPublicKey = crypto.CompressPubkey(&key.PublicKey)
	evidence.Profile = []byte(profile)
	intermediate, err := os.ReadFile(filepath.Join(dir, "intermediate.pem"))
	must(err)
	block, _ := pem.Decode(intermediate)
	if block == nil {
		log.Fatal("invalid intermediate PEM")
	}
	evidence.EKIntermediatesDER = [][]byte{block.Bytes}
	validated, err := policy().ValidateEvidence(big.NewInt(chainID), tpmregistry.DefaultRegistryAddress, &evidence)
	must(err)
	identity := nodeIdentity{Controller: crypto.PubkeyToAddress(key.PublicKey), DID: validated.DID, Evidence: evidence}
	must(writeJSON(filepath.Join(dir, "identity.json"), identity))
	must(writeNew(filepath.Join(dir, "vrf.pub"), []byte(hex.EncodeToString(evidence.VRFPublicKey))))
	must(writeNew(filepath.Join(dir, "profile.bin"), []byte(profile)))
	must(writeNew(filepath.Join(dir, "password"), []byte("\n")))
	fmt.Printf("controller=%s did=%s profileHash=%s\n", identity.Controller, identity.DID, validated.ProfileHash)
}

func genesis(dir string, files []string) {
	if len(files) != 5 {
		log.Fatal("five public identity files required")
	}
	p := policy()
	digest, err := p.Digest()
	must(err)
	identities := make([]nodeIdentity, 5)
	values := make([]*tpmregistry.ValidatedEvidence, 5)
	seen := make(map[common.Hash]bool)
	for i, file := range files {
		raw, err := os.ReadFile(file)
		must(err)
		must(json.Unmarshal(raw, &identities[i]))
		v, err := p.ValidateEvidence(big.NewInt(chainID), tpmregistry.DefaultRegistryAddress, &identities[i].Evidence)
		must(err)
		if seen[v.DeviceNullifier] {
			log.Fatal("duplicate or invalid identity")
		}
		// DID is chain-bound; derive it again from validated evidence for this new chain.
		identities[i].DID = v.DID
		pub, err := crypto.DecompressPubkey(identities[i].Evidence.VRFPublicKey)
		must(err)
		if crypto.PubkeyToAddress(*pub) != identities[i].Controller {
			log.Fatal("controller/VRF mismatch")
		}
		seen[v.DeviceNullifier] = true
		values[i] = v
	}
	config := *params.DaejeonChainConfig
	config.ChainID = big.NewInt(chainID)
	config.VCTBlock = big.NewInt(1)
	config.TPMGatedBlock = big.NewInt(1)
	config.TPMRegistryBlock = nil
	config.TPMRegistry = nil
	config.Vct = &params.VctConfig{MinimumDifficulty: 4096, SeedDelay: 1, MinEligibleBalance: new(big.Int), InitialEligibilityThreshold: big.NewInt(256)}
	g := &core.Genesis{Config: &config, Nonce: chainID, Timestamp: uint64(time.Now().Unix() - 1), ExtraData: []byte("TGPoW GCP 4096 demo"), GasLimit: 30000000, Difficulty: big.NewInt(4096), BaseFee: new(big.Int).SetUint64(params.InitialBaseFee), Alloc: make(core.GenesisAlloc)}
	funding, _ := new(big.Int).SetString("1000000000000000000000000", 10)
	for _, id := range identities {
		g.Alloc[id.Controller] = core.GenesisAccount{Balance: new(big.Int).Set(funding)}
	}
	must(registrygenesis.Apply(g, tpmregistry.PredeployConfig{Address: tpmregistry.DefaultRegistryAddress, FixedCollateral: new(big.Int), Governor: identities[0].Controller, RegistrationTTL: 180, ActivationDelay: 6, ProducerSlotCount: 6, ProducerThreshold: 2, ProducerSlotDelay: 2, ProducerResponseWindow: 60, ProducerPolicyDigest: digest}))
	account := g.Alloc[tpmregistry.DefaultRegistryAddress]
	for i := 0; i < 2; i++ {
		v := values[i]
		must(tpmregistry.AddBootstrapRegistration(account.Storage, tpmregistry.BootstrapRegistration{DID: v.DID, Controller: identities[i].Controller, WorkKeyHash: v.WorkKeyHash, VRFKeyHash: v.VRFKeyHash, ProfileHash: v.ProfileHash, DeviceNullifier: v.DeviceNullifier}))
	}
	g.Alloc[tpmregistry.DefaultRegistryAddress] = account
	must(g.Config.CheckConfigForkOrder())
	must(writeJSON(filepath.Join(dir, "genesis.json"), g))
	must(writeJSON(filepath.Join(dir, "manifest.json"), map[string]interface{}{"chainId": chainID, "policyDigest": digest, "profileHash": crypto.Keccak256Hash([]byte(profile)), "bootstrapCount": 2, "activationDelay": 6, "producerSlots": 6, "producerThreshold": 2, "initialEligibility": 256, "identities": identities}))
	fmt.Printf("genesis prepared: chain=%d policy=%s bootstrap=2 late=3\n", chainID, digest)
}

func writeNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func writeJSON(path string, v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeNew(path, append(b, '\n'))
}
func must(err error) {
	if err != nil {
		log.Fatal(strings.TrimSpace(err.Error()))
	}
}
