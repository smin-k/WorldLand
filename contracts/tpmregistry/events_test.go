package tpmregistry

import (
	"math/big"
	"testing"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/core/types"
)

func TestParseProducerEvents(t *testing.T) {
	requestID := common.HexToHash("0x01")
	identity := common.HexToHash("0x02")
	controller := common.HexToAddress("0x1234")
	statement := common.HexToHash("0x03")
	bundle := []byte("enrollment evidence")
	data, err := parsedProducerEvents.Events["ProducerRegistrationRequested"].Inputs.NonIndexed().Pack(
		uint64(10), uint64(15), uint64(30), statement, bundle,
	)
	if err != nil {
		t.Fatal(err)
	}
	registration, err := ParseProducerRegistrationEvent(types.Log{
		Topics: []common.Hash{
			ProducerEventTopic("ProducerRegistrationRequested"), requestID, identity,
			common.BytesToHash(controller.Bytes()),
		},
		Data: data, BlockNumber: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if registration.RequestID != requestID || registration.Identity != identity || registration.Controller != controller ||
		registration.FirstSlot != 10 || registration.LastSlot != 15 || registration.ResponseDeadline != 30 ||
		registration.StatementHash != statement || string(registration.EvidenceBundle) != string(bundle) {
		t.Fatalf("unexpected registration event: %+v", registration)
	}

	commitment := common.HexToHash("0x04")
	data, err = parsedProducerEvents.Events["ProducerChallengePublished"].Inputs.NonIndexed().Pack(
		[]byte("credential"), []byte("encrypted"), commitment,
	)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := ParseProducerChallengeEvent(types.Log{
		Topics: []common.Hash{
			ProducerEventTopic("ProducerChallengePublished"), requestID,
			common.BigToHash(big.NewInt(11)), common.BytesToHash(controller.Bytes()),
		},
		Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Slot != 11 || challenge.Producer != controller || challenge.Commitment != commitment ||
		string(challenge.CredentialBlob) != "credential" || string(challenge.EncryptedSecret) != "encrypted" {
		t.Fatalf("unexpected challenge event: %+v", challenge)
	}

	evidenceHash := common.HexToHash("0x05")
	data, err = parsedProducerEvents.Events["ProducerResponseSubmitted"].Inputs.NonIndexed().Pack([]byte("response evidence"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := ParseProducerResponseEvent(types.Log{
		Topics: []common.Hash{
			ProducerEventTopic("ProducerResponseSubmitted"), requestID,
			common.BigToHash(big.NewInt(11)), evidenceHash,
		},
		Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Slot != 11 || response.EvidenceHash != evidenceHash || string(response.EvidenceBundle) != "response evidence" {
		t.Fatalf("unexpected response event: %+v", response)
	}
}
