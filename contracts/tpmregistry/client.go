package tpmregistry

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/cryptoecc/WorldLand/accounts/abi"
	"github.com/cryptoecc/WorldLand/accounts/abi/bind"
	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/core/types"
)

const RegistryABI = `[
 {"inputs":[{"components":[{"name":"did","type":"bytes32"},{"name":"workKeyHash","type":"bytes32"},{"name":"vrfKeyHash","type":"bytes32"},{"name":"profileHash","type":"bytes32"},{"name":"deviceNullifier","type":"bytes32"},{"name":"evidenceHash","type":"bytes32"}],"name":"enrollment","type":"tuple"}],"name":"beginRegistration","outputs":[{"name":"requestId","type":"bytes32"}],"stateMutability":"payable","type":"function"},
 {"inputs":[{"components":[{"name":"did","type":"bytes32"},{"name":"workKeyHash","type":"bytes32"},{"name":"vrfKeyHash","type":"bytes32"},{"name":"profileHash","type":"bytes32"},{"name":"deviceNullifier","type":"bytes32"},{"name":"evidenceHash","type":"bytes32"}],"name":"enrollment","type":"tuple"},{"name":"evidenceBundle","type":"bytes"}],"name":"beginProducerRegistration","outputs":[{"name":"requestId","type":"bytes32"}],"stateMutability":"payable","type":"function"},
 {"inputs":[{"name":"requestId","type":"bytes32"},{"name":"credentialBlob","type":"bytes"},{"name":"encryptedSecret","type":"bytes"},{"name":"commitment","type":"bytes32"},{"name":"producerSignature","type":"bytes"}],"name":"publishProducerChallenge","outputs":[],"stateMutability":"nonpayable","type":"function"},
 {"inputs":[{"name":"requestId","type":"bytes32"},{"name":"slot","type":"uint64"},{"name":"secret","type":"bytes32"},{"name":"evidenceBundle","type":"bytes"}],"name":"submitProducerResponse","outputs":[],"stateMutability":"nonpayable","type":"function"},
 {"inputs":[{"name":"requestId","type":"bytes32"},{"name":"slot","type":"uint64"},{"name":"identity","type":"bytes32"},{"name":"producerSignature","type":"bytes"}],"name":"approveProducerSlot","outputs":[],"stateMutability":"nonpayable","type":"function"},
 {"inputs":[{"name":"requestId","type":"bytes32"},{"components":[{"name":"did","type":"bytes32"},{"name":"workKeyHash","type":"bytes32"},{"name":"vrfKeyHash","type":"bytes32"},{"name":"profileHash","type":"bytes32"},{"name":"deviceNullifier","type":"bytes32"},{"name":"evidenceHash","type":"bytes32"}],"name":"enrollment","type":"tuple"}],"name":"finalizeProducerRegistration","outputs":[],"stateMutability":"nonpayable","type":"function"},
 {"inputs":[{"name":"requestId","type":"bytes32"},{"components":[{"name":"did","type":"bytes32"},{"name":"workKeyHash","type":"bytes32"},{"name":"vrfKeyHash","type":"bytes32"},{"name":"profileHash","type":"bytes32"},{"name":"deviceNullifier","type":"bytes32"},{"name":"evidenceHash","type":"bytes32"}],"name":"enrollment","type":"tuple"},{"name":"approvals","type":"bytes[]"}],"name":"finalizeRegistration","outputs":[],"stateMutability":"nonpayable","type":"function"},
 {"inputs":[{"name":"did","type":"bytes32"}],"name":"activate","outputs":[],"stateMutability":"nonpayable","type":"function"},
 {"inputs":[{"name":"did","type":"bytes32"}],"name":"revoke","outputs":[],"stateMutability":"nonpayable","type":"function"},
 {"inputs":[{"name":"requestId","type":"bytes32"}],"name":"cancelExpired","outputs":[],"stateMutability":"nonpayable","type":"function"},
 {"inputs":[],"name":"fixedCollateral","outputs":[{"type":"uint256"}],"stateMutability":"view","type":"function"},
 {"inputs":[{"type":"address"}],"name":"requestNonce","outputs":[{"type":"uint256"}],"stateMutability":"view","type":"function"},
 {"inputs":[{"type":"bytes32"}],"name":"requests","outputs":[{"name":"controller","type":"address"},{"name":"validatorEpoch","type":"uint64"},{"name":"deadline","type":"uint64"},{"name":"finalized","type":"bool"},{"name":"statementHash","type":"bytes32"},{"name":"collateral","type":"uint256"}],"stateMutability":"view","type":"function"},
 {"inputs":[{"type":"uint64"}],"name":"policyDigestByEpoch","outputs":[{"type":"bytes32"}],"stateMutability":"view","type":"function"},
 {"inputs":[{"type":"uint64"}],"name":"thresholdByEpoch","outputs":[{"type":"uint16"}],"stateMutability":"view","type":"function"},
 {"inputs":[{"type":"uint64"},{"type":"address"}],"name":"validatorByEpoch","outputs":[{"type":"bool"}],"stateMutability":"view","type":"function"},
 {"inputs":[{"type":"bytes32"}],"name":"activationBlockByDID","outputs":[{"type":"uint256"}],"stateMutability":"view","type":"function"},
 {"inputs":[{"type":"bytes32"}],"name":"producerRequests","outputs":[{"name":"firstSlot","type":"uint64"},{"name":"lastSlot","type":"uint64"},{"name":"responseDeadline","type":"uint64"},{"name":"threshold","type":"uint16"},{"name":"approvals","type":"uint16"}],"stateMutability":"view","type":"function"},
 {"inputs":[{"type":"bytes32"}],"name":"producerRequestPolicyDigest","outputs":[{"type":"bytes32"}],"stateMutability":"view","type":"function"},
 {"inputs":[{"type":"bytes32"},{"type":"uint64"}],"name":"producerSlots","outputs":[{"name":"producer","type":"address"},{"name":"credentialHash","type":"bytes32"},{"name":"commitment","type":"bytes32"},{"name":"evidenceHash","type":"bytes32"},{"name":"responded","type":"bool"},{"name":"approved","type":"bool"}],"stateMutability":"view","type":"function"},
 {"inputs":[{"name":"requestId","type":"bytes32"},{"name":"statementHash","type":"bytes32"},{"name":"slot","type":"uint64"},{"name":"producer","type":"address"},{"name":"credentialHash","type":"bytes32"},{"name":"secret","type":"bytes32"}],"name":"producerChallengeCommitment","outputs":[{"type":"bytes32"}],"stateMutability":"view","type":"function"},
 {"inputs":[{"name":"requestId","type":"bytes32"},{"name":"slot","type":"uint64"},{"name":"producer","type":"address"},{"name":"credentialHash","type":"bytes32"},{"name":"commitment","type":"bytes32"}],"name":"producerChallengeDigest","outputs":[{"type":"bytes32"}],"stateMutability":"view","type":"function"},
 {"inputs":[{"name":"requestId","type":"bytes32"},{"name":"slot","type":"uint64"},{"name":"commitment","type":"bytes32"},{"name":"evidenceHash","type":"bytes32"},{"name":"identity","type":"bytes32"},{"name":"deadline","type":"uint64"}],"name":"producerApprovalDigest","outputs":[{"type":"bytes32"}],"stateMutability":"view","type":"function"},
 {"inputs":[{"name":"requestId","type":"bytes32"},{"name":"slot","type":"uint64"},{"name":"commitment","type":"bytes32"}],"name":"producerCertifyChallenge","outputs":[{"type":"bytes32"}],"stateMutability":"view","type":"function"},
 {"inputs":[{"name":"did","type":"bytes32"}],"name":"registration","outputs":[{"name":"controller","type":"address"},{"name":"workKeyHash","type":"bytes32"},{"name":"vrfKeyHash","type":"bytes32"},{"name":"profileHash","type":"bytes32"},{"name":"deviceNullifier","type":"bytes32"},{"name":"active","type":"bool"}],"stateMutability":"view","type":"function"}
]`

type EnrollmentData struct {
	DID             common.Hash `abi:"did"`
	WorkKeyHash     common.Hash `abi:"workKeyHash"`
	VRFKeyHash      common.Hash `abi:"vrfKeyHash"`
	ProfileHash     common.Hash `abi:"profileHash"`
	DeviceNullifier common.Hash `abi:"deviceNullifier"`
	EvidenceHash    common.Hash `abi:"evidenceHash"`
}

type RegistrationRequestState struct {
	Controller     common.Address
	ValidatorEpoch uint64
	Deadline       uint64
	Finalized      bool
	StatementHash  common.Hash
	Collateral     *big.Int
}

type RegistrationState struct {
	Controller      common.Address `abi:"controller"`
	WorkKeyHash     common.Hash    `abi:"workKeyHash"`
	VRFKeyHash      common.Hash    `abi:"vrfKeyHash"`
	ProfileHash     common.Hash    `abi:"profileHash"`
	DeviceNullifier common.Hash    `abi:"deviceNullifier"`
	Active          bool           `abi:"active"`
}

type ProducerRequestState struct {
	FirstSlot        uint64
	LastSlot         uint64
	ResponseDeadline uint64
	Threshold        uint16
	Approvals        uint16
}

type ProducerSlotState struct {
	Producer       common.Address
	CredentialHash common.Hash
	Commitment     common.Hash
	EvidenceHash   common.Hash
	Responded      bool
	Approved       bool
}

type RegistryClient struct {
	address  common.Address
	contract *bind.BoundContract
}

func NewRegistryClient(address common.Address, backend bind.ContractBackend) (*RegistryClient, error) {
	if backend == nil || address == (common.Address{}) {
		return nil, errors.New("tpmregistry: registry backend and address are required")
	}
	parsed, err := abi.JSON(strings.NewReader(RegistryABI))
	if err != nil {
		return nil, err
	}
	return &RegistryClient{address: address, contract: bind.NewBoundContract(address, parsed, backend, backend, backend)}, nil
}

// PackRegistryCall ABI-encodes a registry method for private candidate-block
// transactions and other offline signing workflows.
func PackRegistryCall(method string, parameters ...interface{}) ([]byte, error) {
	parsed, err := abi.JSON(strings.NewReader(RegistryABI))
	if err != nil {
		return nil, err
	}
	return parsed.Pack(method, parameters...)
}

func (client *RegistryClient) FixedCollateral(ctx context.Context) (*big.Int, error) {
	values, err := client.call(ctx, "fixedCollateral")
	if err != nil {
		return nil, err
	}
	value, ok := values[0].(*big.Int)
	if !ok {
		return nil, errors.New("tpmregistry: malformed collateral")
	}
	return value, nil
}

func (client *RegistryClient) RequestNonce(ctx context.Context, controller common.Address) (*big.Int, error) {
	values, err := client.call(ctx, "requestNonce", controller)
	if err != nil {
		return nil, err
	}
	value, ok := values[0].(*big.Int)
	if !ok {
		return nil, errors.New("tpmregistry: malformed request nonce")
	}
	return value, nil
}

func (client *RegistryClient) Request(ctx context.Context, requestID common.Hash) (RegistrationRequestState, error) {
	values, err := client.call(ctx, "requests", requestID)
	if err != nil {
		return RegistrationRequestState{}, err
	}
	if len(values) != 6 {
		return RegistrationRequestState{}, errors.New("tpmregistry: malformed request")
	}
	controller, ok0 := values[0].(common.Address)
	epoch, ok1 := values[1].(uint64)
	deadline, ok2 := values[2].(uint64)
	finalized, ok3 := values[3].(bool)
	hashValue, ok4 := values[4].([32]byte)
	collateral, ok5 := values[5].(*big.Int)
	if !ok0 || !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return RegistrationRequestState{}, errors.New("tpmregistry: malformed request fields")
	}
	return RegistrationRequestState{controller, epoch, deadline, finalized, common.Hash(hashValue), collateral}, nil
}

func (client *RegistryClient) PolicyDigest(ctx context.Context, epoch uint64) (common.Hash, error) {
	values, err := client.call(ctx, "policyDigestByEpoch", epoch)
	if err != nil {
		return common.Hash{}, err
	}
	value, ok := values[0].([32]byte)
	if !ok {
		return common.Hash{}, errors.New("tpmregistry: malformed policy digest")
	}
	return common.Hash(value), nil
}

func (client *RegistryClient) Threshold(ctx context.Context, epoch uint64) (uint16, error) {
	values, err := client.call(ctx, "thresholdByEpoch", epoch)
	if err != nil {
		return 0, err
	}
	value, ok := values[0].(uint16)
	if !ok {
		return 0, errors.New("tpmregistry: malformed threshold")
	}
	return value, nil
}

func (client *RegistryClient) IsValidator(ctx context.Context, epoch uint64, validator common.Address) (bool, error) {
	values, err := client.call(ctx, "validatorByEpoch", epoch, validator)
	if err != nil {
		return false, err
	}
	value, ok := values[0].(bool)
	if !ok {
		return false, errors.New("tpmregistry: malformed validator membership")
	}
	return value, nil
}

func (client *RegistryClient) ActivationBlock(ctx context.Context, did common.Hash) (*big.Int, error) {
	values, err := client.call(ctx, "activationBlockByDID", did)
	if err != nil {
		return nil, err
	}
	value, ok := values[0].(*big.Int)
	if !ok {
		return nil, errors.New("tpmregistry: malformed activation block")
	}
	return value, nil
}

func (client *RegistryClient) Registration(ctx context.Context, did common.Hash) (RegistrationState, error) {
	values, err := client.call(ctx, "registration", did)
	if err != nil {
		return RegistrationState{}, err
	}
	if len(values) != 6 {
		return RegistrationState{}, errors.New("tpmregistry: malformed registration")
	}
	controller, ok0 := values[0].(common.Address)
	work, ok1 := values[1].([32]byte)
	vrf, ok2 := values[2].([32]byte)
	profile, ok3 := values[3].([32]byte)
	nullifier, ok4 := values[4].([32]byte)
	active, ok5 := values[5].(bool)
	if !ok0 || !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return RegistrationState{}, errors.New("tpmregistry: malformed registration fields")
	}
	return RegistrationState{controller, common.Hash(work), common.Hash(vrf), common.Hash(profile), common.Hash(nullifier), active}, nil
}

func (client *RegistryClient) ProducerRequest(ctx context.Context, requestID common.Hash) (ProducerRequestState, error) {
	values, err := client.call(ctx, "producerRequests", requestID)
	if err != nil {
		return ProducerRequestState{}, err
	}
	if len(values) != 5 {
		return ProducerRequestState{}, errors.New("tpmregistry: malformed producer request")
	}
	first, ok0 := values[0].(uint64)
	last, ok1 := values[1].(uint64)
	deadline, ok2 := values[2].(uint64)
	threshold, ok3 := values[3].(uint16)
	approvals, ok4 := values[4].(uint16)
	if !ok0 || !ok1 || !ok2 || !ok3 || !ok4 {
		return ProducerRequestState{}, errors.New("tpmregistry: malformed producer request fields")
	}
	return ProducerRequestState{first, last, deadline, threshold, approvals}, nil
}

func (client *RegistryClient) ProducerRequestPolicyDigest(ctx context.Context, requestID common.Hash) (common.Hash, error) {
	return client.hashCall(ctx, "producerRequestPolicyDigest", requestID)
}

func (client *RegistryClient) ProducerSlot(ctx context.Context, requestID common.Hash, slot uint64) (ProducerSlotState, error) {
	values, err := client.call(ctx, "producerSlots", requestID, slot)
	if err != nil {
		return ProducerSlotState{}, err
	}
	if len(values) != 6 {
		return ProducerSlotState{}, errors.New("tpmregistry: malformed producer slot")
	}
	producer, ok0 := values[0].(common.Address)
	credential, ok1 := values[1].([32]byte)
	commitment, ok2 := values[2].([32]byte)
	evidence, ok3 := values[3].([32]byte)
	responded, ok4 := values[4].(bool)
	approved, ok5 := values[5].(bool)
	if !ok0 || !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return ProducerSlotState{}, errors.New("tpmregistry: malformed producer slot fields")
	}
	return ProducerSlotState{producer, common.Hash(credential), common.Hash(commitment), common.Hash(evidence), responded, approved}, nil
}

func (client *RegistryClient) ProducerChallengeCommitment(ctx context.Context, requestID, statementHash common.Hash, slot uint64, producer common.Address, credentialHash, secret common.Hash) (common.Hash, error) {
	return client.hashCall(ctx, "producerChallengeCommitment", requestID, statementHash, slot, producer, credentialHash, secret)
}

func (client *RegistryClient) ProducerChallengeDigest(ctx context.Context, requestID common.Hash, slot uint64, producer common.Address, credentialHash, commitment common.Hash) (common.Hash, error) {
	return client.hashCall(ctx, "producerChallengeDigest", requestID, slot, producer, credentialHash, commitment)
}

func (client *RegistryClient) ProducerApprovalDigest(ctx context.Context, requestID common.Hash, slot uint64, commitment, evidenceHash, identity common.Hash, deadline uint64) (common.Hash, error) {
	return client.hashCall(ctx, "producerApprovalDigest", requestID, slot, commitment, evidenceHash, identity, deadline)
}

func (client *RegistryClient) ProducerCertifyChallenge(ctx context.Context, requestID common.Hash, slot uint64, commitment common.Hash) (common.Hash, error) {
	return client.hashCall(ctx, "producerCertifyChallenge", requestID, slot, commitment)
}

func (client *RegistryClient) hashCall(ctx context.Context, method string, parameters ...interface{}) (common.Hash, error) {
	values, err := client.call(ctx, method, parameters...)
	if err != nil {
		return common.Hash{}, err
	}
	value, ok := values[0].([32]byte)
	if !ok {
		return common.Hash{}, fmt.Errorf("tpmregistry: malformed %s hash", method)
	}
	return common.Hash(value), nil
}

func (client *RegistryClient) Begin(opts *bind.TransactOpts, enrollment EnrollmentData) (*types.Transaction, error) {
	return client.contract.Transact(opts, "beginRegistration", enrollment)
}

func (client *RegistryClient) BeginProducer(opts *bind.TransactOpts, enrollment EnrollmentData, evidenceBundle []byte) (*types.Transaction, error) {
	return client.contract.Transact(opts, "beginProducerRegistration", enrollment, evidenceBundle)
}

func (client *RegistryClient) PublishProducerChallenge(opts *bind.TransactOpts, requestID common.Hash, credentialBlob, encryptedSecret []byte, commitment common.Hash, signature []byte) (*types.Transaction, error) {
	return client.contract.Transact(opts, "publishProducerChallenge", requestID, credentialBlob, encryptedSecret, commitment, signature)
}

func (client *RegistryClient) SubmitProducerResponse(opts *bind.TransactOpts, requestID common.Hash, slot uint64, secret common.Hash, evidenceBundle []byte) (*types.Transaction, error) {
	return client.contract.Transact(opts, "submitProducerResponse", requestID, slot, secret, evidenceBundle)
}

func (client *RegistryClient) ApproveProducerSlot(opts *bind.TransactOpts, requestID common.Hash, slot uint64, identity common.Hash, signature []byte) (*types.Transaction, error) {
	return client.contract.Transact(opts, "approveProducerSlot", requestID, slot, identity, signature)
}

func (client *RegistryClient) FinalizeProducer(opts *bind.TransactOpts, requestID common.Hash, enrollment EnrollmentData) (*types.Transaction, error) {
	return client.contract.Transact(opts, "finalizeProducerRegistration", requestID, enrollment)
}

func (client *RegistryClient) Finalize(opts *bind.TransactOpts, requestID common.Hash, enrollment EnrollmentData, approvals [][]byte) (*types.Transaction, error) {
	return client.contract.Transact(opts, "finalizeRegistration", requestID, enrollment, approvals)
}

func (client *RegistryClient) Activate(opts *bind.TransactOpts, did common.Hash) (*types.Transaction, error) {
	return client.contract.Transact(opts, "activate", did)
}

func (client *RegistryClient) Revoke(opts *bind.TransactOpts, did common.Hash) (*types.Transaction, error) {
	return client.contract.Transact(opts, "revoke", did)
}

func (client *RegistryClient) CancelExpired(opts *bind.TransactOpts, requestID common.Hash) (*types.Transaction, error) {
	return client.contract.Transact(opts, "cancelExpired", requestID)
}

func (client *RegistryClient) call(ctx context.Context, method string, parameters ...interface{}) ([]interface{}, error) {
	var values []interface{}
	if err := client.contract.Call(&bind.CallOpts{Context: ctx}, &values, method, parameters...); err != nil {
		return nil, fmt.Errorf("tpmregistry: call %s: %w", method, err)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("tpmregistry: call %s returned no values", method)
	}
	return values, nil
}
