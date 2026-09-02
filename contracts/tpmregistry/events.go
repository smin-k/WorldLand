package tpmregistry

import (
	"errors"
	"math/big"
	"strings"

	"github.com/cryptoecc/WorldLand/accounts/abi"
	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/core/types"
)

const producerEventsABI = `[
 {"anonymous":false,"inputs":[{"indexed":true,"name":"requestId","type":"bytes32"},{"indexed":true,"name":"identity","type":"bytes32"},{"indexed":true,"name":"controller","type":"address"},{"indexed":false,"name":"firstSlot","type":"uint64"},{"indexed":false,"name":"lastSlot","type":"uint64"},{"indexed":false,"name":"responseDeadline","type":"uint64"},{"indexed":false,"name":"statementHash","type":"bytes32"},{"indexed":false,"name":"evidenceBundle","type":"bytes"}],"name":"ProducerRegistrationRequested","type":"event"},
 {"anonymous":false,"inputs":[{"indexed":true,"name":"requestId","type":"bytes32"},{"indexed":true,"name":"slot","type":"uint64"},{"indexed":true,"name":"producer","type":"address"},{"indexed":false,"name":"credentialBlob","type":"bytes"},{"indexed":false,"name":"encryptedSecret","type":"bytes"},{"indexed":false,"name":"commitment","type":"bytes32"}],"name":"ProducerChallengePublished","type":"event"},
 {"anonymous":false,"inputs":[{"indexed":true,"name":"requestId","type":"bytes32"},{"indexed":true,"name":"slot","type":"uint64"},{"indexed":true,"name":"evidenceHash","type":"bytes32"},{"indexed":false,"name":"evidenceBundle","type":"bytes"}],"name":"ProducerResponseSubmitted","type":"event"},
 {"anonymous":false,"inputs":[{"indexed":true,"name":"requestId","type":"bytes32"},{"indexed":true,"name":"slot","type":"uint64"},{"indexed":true,"name":"producer","type":"address"}],"name":"ProducerSlotApproved","type":"event"}
]`

var parsedProducerEvents = mustProducerEventsABI()

type ProducerRegistrationEvent struct {
	RequestID        common.Hash
	Identity         common.Hash
	Controller       common.Address
	FirstSlot        uint64
	LastSlot         uint64
	ResponseDeadline uint64
	StatementHash    common.Hash
	EvidenceBundle   []byte
	BlockNumber      uint64
	Removed          bool
}

type ProducerChallengeEvent struct {
	RequestID       common.Hash
	Slot            uint64
	Producer        common.Address
	CredentialBlob  []byte
	EncryptedSecret []byte
	Commitment      common.Hash
	Removed         bool
}

type ProducerResponseEvent struct {
	RequestID      common.Hash
	Slot           uint64
	EvidenceHash   common.Hash
	EvidenceBundle []byte
	Removed        bool
}

func ProducerEventTopic(name string) common.Hash {
	return parsedProducerEvents.Events[name].ID
}

func ParseProducerRegistrationEvent(entry types.Log) (ProducerRegistrationEvent, error) {
	if err := checkProducerEvent(entry, "ProducerRegistrationRequested", 4); err != nil {
		return ProducerRegistrationEvent{}, err
	}
	values, err := parsedProducerEvents.Events["ProducerRegistrationRequested"].Inputs.NonIndexed().Unpack(entry.Data)
	if err != nil || len(values) != 5 {
		return ProducerRegistrationEvent{}, errors.New("tpmregistry: malformed producer registration event")
	}
	first, ok0 := values[0].(uint64)
	last, ok1 := values[1].(uint64)
	deadline, ok2 := values[2].(uint64)
	statement, ok3 := values[3].([32]byte)
	bundle, ok4 := values[4].([]byte)
	if !ok0 || !ok1 || !ok2 || !ok3 || !ok4 {
		return ProducerRegistrationEvent{}, errors.New("tpmregistry: malformed producer registration fields")
	}
	return ProducerRegistrationEvent{
		RequestID: common.Hash(entry.Topics[1]), Identity: common.Hash(entry.Topics[2]),
		Controller: common.BytesToAddress(entry.Topics[3][12:]), FirstSlot: first, LastSlot: last,
		ResponseDeadline: deadline, StatementHash: common.Hash(statement), EvidenceBundle: bundle,
		BlockNumber: entry.BlockNumber, Removed: entry.Removed,
	}, nil
}

func ParseProducerChallengeEvent(entry types.Log) (ProducerChallengeEvent, error) {
	if err := checkProducerEvent(entry, "ProducerChallengePublished", 4); err != nil {
		return ProducerChallengeEvent{}, err
	}
	values, err := parsedProducerEvents.Events["ProducerChallengePublished"].Inputs.NonIndexed().Unpack(entry.Data)
	if err != nil || len(values) != 3 {
		return ProducerChallengeEvent{}, errors.New("tpmregistry: malformed producer challenge event")
	}
	blob, ok0 := values[0].([]byte)
	encrypted, ok1 := values[1].([]byte)
	commitment, ok2 := values[2].([32]byte)
	if !ok0 || !ok1 || !ok2 {
		return ProducerChallengeEvent{}, errors.New("tpmregistry: malformed producer challenge fields")
	}
	return ProducerChallengeEvent{
		RequestID: common.Hash(entry.Topics[1]), Slot: new(big.Int).SetBytes(entry.Topics[2][:]).Uint64(),
		Producer: common.BytesToAddress(entry.Topics[3][12:]), CredentialBlob: blob,
		EncryptedSecret: encrypted, Commitment: common.Hash(commitment), Removed: entry.Removed,
	}, nil
}

func ParseProducerResponseEvent(entry types.Log) (ProducerResponseEvent, error) {
	if err := checkProducerEvent(entry, "ProducerResponseSubmitted", 4); err != nil {
		return ProducerResponseEvent{}, err
	}
	values, err := parsedProducerEvents.Events["ProducerResponseSubmitted"].Inputs.NonIndexed().Unpack(entry.Data)
	if err != nil || len(values) != 1 {
		return ProducerResponseEvent{}, errors.New("tpmregistry: malformed producer response event")
	}
	bundle, ok := values[0].([]byte)
	if !ok {
		return ProducerResponseEvent{}, errors.New("tpmregistry: malformed producer response fields")
	}
	return ProducerResponseEvent{
		RequestID: common.Hash(entry.Topics[1]), Slot: new(big.Int).SetBytes(entry.Topics[2][:]).Uint64(),
		EvidenceHash: common.Hash(entry.Topics[3]), EvidenceBundle: bundle, Removed: entry.Removed,
	}, nil
}

func checkProducerEvent(entry types.Log, name string, topics int) error {
	if len(entry.Topics) != topics || entry.Topics[0] != ProducerEventTopic(name) {
		return errors.New("tpmregistry: unexpected producer event")
	}
	return nil
}

func mustProducerEventsABI() abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(producerEventsABI))
	if err != nil {
		panic(err)
	}
	return parsed
}
