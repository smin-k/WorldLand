package main

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	ethereum "github.com/cryptoecc/WorldLand"
	"github.com/cryptoecc/WorldLand/accounts/abi"
	"github.com/cryptoecc/WorldLand/accounts/abi/bind"
	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
)

type lifecycleFixture struct {
	header        *types.Header
	log           types.Log
	slot          tpmregistry.ProducerSlotState
	responses     int
	active        bool
	activateCalls int
	activateRace  bool
	finalized     bool
	requestID     common.Hash
}

func (f *lifecycleFixture) BlockNumber(context.Context) (uint64, error) { return 15, nil }
func (f *lifecycleFixture) HeaderByNumber(context.Context, *big.Int) (*types.Header, error) {
	return f.header, nil
}
func (f *lifecycleFixture) FilterLogs(context.Context, ethereum.FilterQuery) ([]types.Log, error) {
	if f.responses == 1 {
		// Replace the challenge and remove its successful response at exactly
		// the same slot; the old responded[slot] implementation skipped this.
		f.header = &types.Header{Number: big.NewInt(12), Time: 2}
		f.log.BlockHash = f.header.Hash()
		f.slot.Commitment = common.HexToHash("0x789")
		copy(f.log.Data[64:96], f.slot.Commitment[:])
		f.slot.Responded = false
	}
	return []types.Log{f.log}, nil
}
func (f *lifecycleFixture) TransactionReceipt(context.Context, common.Hash) (*types.Receipt, error) {
	return &types.Receipt{Status: types.ReceiptStatusSuccessful}, nil
}
func (f *lifecycleFixture) CodeAt(context.Context, common.Address, *big.Int) ([]byte, error) {
	return []byte{1}, nil
}
func (f *lifecycleFixture) ActivationBlock(context.Context, common.Hash) (*big.Int, error) {
	return big.NewInt(10), nil
}
func (f *lifecycleFixture) Registration(context.Context, common.Hash) (tpmregistry.RegistrationState, error) {
	return tpmregistry.RegistrationState{Active: f.active}, nil
}
func (f *lifecycleFixture) Activate(*bind.TransactOpts, common.Hash) (*types.Transaction, error) {
	f.activateCalls++
	f.active = true
	if f.activateRace {
		return nil, errors.New("TPMRegistry: DID active")
	}
	return lifecycleTx(99), nil
}
func (f *lifecycleFixture) ProducerRequest(context.Context, common.Hash) (tpmregistry.ProducerRequestState, error) {
	approvals := uint16(0)
	if f.responses >= 2 {
		approvals = 1
	}
	return tpmregistry.ProducerRequestState{FirstSlot: 12, LastSlot: 12, ResponseDeadline: 30, Threshold: 1, Approvals: approvals}, nil
}
func (f *lifecycleFixture) ProducerSlot(context.Context, common.Hash, uint64) (tpmregistry.ProducerSlotState, error) {
	return f.slot, nil
}
func (f *lifecycleFixture) SubmitProducerResponse(_ *bind.TransactOpts, _ common.Hash, _ uint64, _ common.Hash, _ []byte) (*types.Transaction, error) {
	f.responses++
	f.slot.Responded = true
	return lifecycleTx(uint64(f.responses)), nil
}
func (f *lifecycleFixture) FinalizeProducer(*bind.TransactOpts, common.Hash, tpmregistry.EnrollmentData) (*types.Transaction, error) {
	f.finalized = true
	return lifecycleTx(100), nil
}
func lifecycleTx(nonce uint64) *types.Transaction {
	return types.NewTransaction(nonce, common.Address{}, new(big.Int), 100_000, big.NewInt(1), nil)
}

type fixtureTPM struct{}

func (fixtureTPM) EnrollmentIdentity(string, bool, uint32, uint32) (*tpmwork.EnrollmentIdentity, error) {
	return nil, errors.New("not used")
}
func (fixtureTPM) ActivateCredential(string, uint32, []byte, []byte) ([]byte, error) {
	return make([]byte, 32), nil
}
func (fixtureTPM) CertifyWorkKey(_ string, _ bool, challenge []byte) (*tpmwork.KeyCertification, error) {
	return &tpmwork.KeyCertification{Version: tpmwork.CertificationVersion, Challenge: challenge}, nil
}

type reorgDuringCertify struct {
	fixtureTPM
	fixture *lifecycleFixture
	cancel  context.CancelFunc
}

func (p reorgDuringCertify) CertifyWorkKey(_ string, _ bool, challenge []byte) (*tpmwork.KeyCertification, error) {
	p.fixture.header = &types.Header{Number: big.NewInt(12), Time: 99}
	p.cancel()
	return &tpmwork.KeyCertification{Version: tpmwork.CertificationVersion, Challenge: challenge}, nil
}

func newLifecycleFixture(t *testing.T) *lifecycleFixture {
	t.Helper()
	requestID := common.HexToHash("0x123")
	producer := common.HexToAddress("0x1234")
	commitment := common.HexToHash("0x456")
	credentialHash, err := tpmregistry.CredentialHash([]byte{1}, []byte{2})
	if err != nil {
		t.Fatal(err)
	}
	bytesType, _ := abi.NewType("bytes", "", nil)
	hashType, _ := abi.NewType("bytes32", "", nil)
	data, err := (abi.Arguments{{Type: bytesType}, {Type: bytesType}, {Type: hashType}}).Pack([]byte{1}, []byte{2}, commitment)
	if err != nil {
		t.Fatal(err)
	}
	header := &types.Header{Number: big.NewInt(12), Time: 1}
	return &lifecycleFixture{
		header: header, requestID: requestID,
		log: types.Log{BlockNumber: 12, BlockHash: header.Hash(), Topics: []common.Hash{
			tpmregistry.ProducerEventTopic("ProducerChallengePublished"), requestID, common.BigToHash(big.NewInt(12)), common.BytesToHash(producer[:]),
		}, Data: data},
		slot: tpmregistry.ProducerSlotState{Producer: producer, Commitment: commitment, CredentialHash: credentialHash},
	}
}

func TestProducerEnrollmentRespondsAgainAfterResponseReorg(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	err := completeProducerRegistration(ctx, commandConfig{chainID: big.NewInt(1337), registry: tpmregistry.DefaultRegistryAddress}, f, f, &bind.TransactOpts{}, fixtureTPM{}, fixtureTPM{}, f.requestID, tpmregistry.EnrollmentData{}, tpmregistry.ProducerRequestState{})
	if err != nil {
		t.Fatal(err)
	}
	if f.responses != 2 || !f.finalized {
		t.Fatalf("responses %d, finalized %v", f.responses, f.finalized)
	}
}

func TestReadCurrentChallengeRejectsReplacedBlockOrCommitment(t *testing.T) {
	f := newLifecycleFixture(t)
	challenge, err := tpmregistry.ParseProducerChallengeEvent(f.log)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := readCurrentChallenge(context.Background(), f, f, f.log, challenge); err != nil || !ok {
		t.Fatalf("fresh challenge: %v, %v", ok, err)
	}
	f.header = &types.Header{Number: big.NewInt(12), Time: 2}
	if _, ok, err := readCurrentChallenge(context.Background(), f, f, f.log, challenge); err != nil || ok {
		t.Fatalf("orphan challenge: %v, %v", ok, err)
	}
	f.log.BlockHash = f.header.Hash()
	f.slot.Commitment = common.HexToHash("0x999")
	if _, ok, err := readCurrentChallenge(context.Background(), f, f, f.log, challenge); err != nil || ok {
		t.Fatalf("replaced commitment: %v, %v", ok, err)
	}
}

func TestProducerEnrollmentDoesNotPublishChallengeReorgedDuringTPMCall(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tpm := reorgDuringCertify{fixture: f, cancel: cancel}
	err := completeProducerRegistration(ctx, commandConfig{chainID: big.NewInt(1337), registry: tpmregistry.DefaultRegistryAddress}, f, f, &bind.TransactOpts{}, tpm, tpm, f.requestID, tpmregistry.EnrollmentData{}, tpmregistry.ProducerRequestState{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation after reorg", err)
	}
	if f.responses != 0 {
		t.Fatal("published response after its challenge block was replaced")
	}
}

func TestFinishActivationIsIdempotent(t *testing.T) {
	for _, test := range []struct {
		name         string
		active, race bool
		calls        int
	}{
		{"zero delay already active", true, false, 0},
		{"another caller activated", false, true, 1},
		{"normal activation", false, false, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := &lifecycleFixture{active: test.active, activateRace: test.race}
			if err := finishActivation(context.Background(), commandConfig{waitActivation: true}, f, f, &bind.TransactOpts{}, common.HexToHash("0x123")); err != nil {
				t.Fatal(err)
			}
			if f.activateCalls != test.calls {
				t.Fatalf("activate calls %d, want %d", f.activateCalls, test.calls)
			}
		})
	}
}

func TestControllerVRFKeyCanonicalEncodingAndOwner(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	controller := crypto.PubkeyToAddress(key.PublicKey)
	compressed := crypto.CompressPubkey(&key.PublicKey)
	for _, encoded := range [][]byte{compressed, crypto.FromECDSAPub(&key.PublicKey)} {
		got, err := validateControllerVRFKey(encoded, controller)
		if err != nil || got != crypto.Keccak256Hash(compressed) {
			t.Fatalf("VRF hash %s, err %v", got, err)
		}
	}
	if _, err := validateControllerVRFKey(compressed, common.Address{}); err == nil || !strings.Contains(err.Error(), "controller") {
		t.Fatalf("wrong controller accepted: %v", err)
	}
	if _, err := validateControllerVRFKey([]byte{1}, controller); err == nil {
		t.Fatal("invalid VRF key accepted")
	}
}
