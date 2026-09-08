package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/common/hexutil"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
)

// queueRPC models the miner's branch-bound queue API, including an acknowledgement
// lost after acceptance. Tests call the production restore/staging methods.
type queueRPC struct {
	parent       common.Hash
	target       uint64
	transactions []hexutil.Bytes
	loseAck      bool
	submissions  int
}

func (q *queueRPC) CallContext(_ context.Context, result interface{}, method string, args ...interface{}) error {
	switch method {
	case "miner_enrollmentQueue":
		if uint64(args[0].(hexutil.Uint64)) != q.target || args[1].(common.Hash) != q.parent {
			return errors.New("stale parent")
		}
		*result.(*enrollmentQueue) = enrollmentQueue{q.parent, hexutil.Uint64(q.target), append([]hexutil.Bytes(nil), q.transactions...)}
		return nil
	case "miner_submitEnrollmentTransaction":
		q.submissions++
		if uint64(args[0].(hexutil.Uint64)) != q.target || args[2].(common.Hash) != q.parent {
			return errors.New("stale parent")
		}
		raw := args[1].(hexutil.Bytes)
		var tx types.Transaction
		if err := tx.UnmarshalBinary(raw); err != nil {
			return err
		}
		for _, existing := range q.transactions {
			var queued types.Transaction
			if err := queued.UnmarshalBinary(existing); err != nil {
				return err
			}
			if queued.Hash() == tx.Hash() {
				*result.(*common.Hash) = tx.Hash()
				return nil
			}
			if queued.Nonce() == tx.Nonce() {
				return errors.New("duplicate private nonce")
			}
		}
		q.transactions = append(q.transactions, raw)
		if q.loseAck {
			q.loseAck = false
			return errors.New("connection lost after acceptance")
		}
		*result.(*common.Hash) = tx.Hash()
		return nil
	default:
		return errors.New("unexpected RPC method")
	}
}

type emptyProducerRegistry struct{}

func (emptyProducerRegistry) Request(context.Context, common.Hash) (tpmregistry.RegistrationRequestState, error) {
	return tpmregistry.RegistrationRequestState{}, nil
}
func (emptyProducerRegistry) ProducerRequest(context.Context, common.Hash) (tpmregistry.ProducerRequestState, error) {
	return tpmregistry.ProducerRequestState{}, nil
}
func (emptyProducerRegistry) ProducerRequestPolicyDigest(context.Context, common.Hash) (common.Hash, error) {
	return common.Hash{}, nil
}
func (emptyProducerRegistry) ProducerSlot(context.Context, common.Hash, uint64) (tpmregistry.ProducerSlotState, error) {
	return tpmregistry.ProducerSlotState{}, nil
}

func newStagingAgent(t *testing.T, limit int) (*producerAgent, *queueRPC) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ek, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// A concrete RSA TPMT_PUBLIC fixture is sufficient for real MakeCredential;
	// evidence-policy acceptance is tested in contracts/tpmregistry.
	area := []byte{0, 1, 0, 11, 0, 0, 0, 0, 0, 0, 0, 16, 0, 16, 8, 0, 0, 1, 0, 1, 1, 0}
	area = append(area, ek.N.FillBytes(make([]byte, 256))...)
	evidence := &tpmregistry.Evidence{EKPublicArea: area, AttestationPublicArea: area}
	queue := &queueRPC{parent: common.HexToHash("0xabc"), target: 12}
	agent := &producerAgent{
		chainID: big.NewInt(1337), registry: tpmregistry.DefaultRegistryAddress,
		key: key, address: crypto.PubkeyToAddress(key.PublicKey), rpc: queue,
		contract: emptyProducerRegistry{}, maxPerSlot: limit, gasLimit: 1_200_000,
		requests: make(map[common.Hash]*trackedRequest), parentHash: queue.parent,
	}
	for i := 5; i > 0; i-- {
		id := common.BigToHash(big.NewInt(int64(i)))
		agent.requests[id] = &trackedRequest{event: tpmregistry.ProducerRegistrationEvent{RequestID: id}, evidence: evidence, state: tpmregistry.ProducerRequestState{FirstSlot: 12, LastSlot: 14}}
	}
	return agent, queue
}

func TestStagingRestoresNonceAfterLostAcknowledgementAndRestart(t *testing.T) {
	agent, queue := newStagingAgent(t, 5)
	queue.loseAck = true
	ctx := context.Background()
	nonce, err := agent.restoreQueue(ctx, 12, 7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = agent.stageChallenges(ctx, 12, nonce, big.NewInt(10)); err == nil {
		t.Fatal("lost acknowledgement was not reported")
	}
	if len(queue.transactions) != 1 {
		t.Fatal("fixture did not accept exactly one transaction")
	}
	// The process loses all local reservations. The miner remains authoritative.
	agent.staged = nil
	nonce, err = agent.restoreQueue(ctx, 12, 7)
	if err != nil || nonce != 8 {
		t.Fatalf("restored nonce %d, err %v", nonce, err)
	}
	if _, err = agent.stageChallenges(ctx, 12, nonce, big.NewInt(10)); err != nil {
		t.Fatal(err)
	}
	if len(queue.transactions) != 5 {
		t.Fatalf("queued %d challenges, want 5", len(queue.transactions))
	}
	for i, raw := range queue.transactions {
		var tx types.Transaction
		if err := tx.UnmarshalBinary(raw); err != nil {
			t.Fatal(err)
		}
		if tx.Nonce() != uint64(7+i) {
			t.Fatalf("transaction %d nonce %d", i, tx.Nonce())
		}
		if got := new(big.Int).SetBytes(tx.Data()[4:36]).Int64(); got != int64(i+1) {
			t.Fatalf("nondeterministic request order: %d", got)
		}
	}
	nonce, err = agent.restoreQueue(ctx, 12, 7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = agent.stageChallenges(ctx, 12, nonce, big.NewInt(10)); err != nil {
		t.Fatal(err)
	}
	if queue.submissions != 5 {
		t.Fatalf("repeated tick submitted duplicates: %d", queue.submissions)
	}
}

func TestStagingCapIsCumulativeAndReorgRestoresNewBranch(t *testing.T) {
	agent, queue := newStagingAgent(t, 4)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		nonce, err := agent.restoreQueue(ctx, 12, 3)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = agent.stageChallenges(ctx, 12, nonce, big.NewInt(10)); err != nil {
			t.Fatal(err)
		}
	}
	if len(queue.transactions) != 4 || queue.submissions != 4 {
		t.Fatal("cap reset across ticks or nonce was reused")
	}
	// The miner discarded A's queue on a same-height reorg. Old staged markers
	// must not suppress fresh challenges on parent B.
	queue.parent = common.HexToHash("0xdef")
	queue.transactions = nil
	agent.parentHash = queue.parent
	nonce, err := agent.restoreQueue(ctx, 12, 9)
	if err != nil || nonce != 9 {
		t.Fatalf("reorg nonce %d, err %v", nonce, err)
	}
	if _, err = agent.stageChallenges(ctx, 12, nonce, big.NewInt(10)); err != nil {
		t.Fatal(err)
	}
	if len(queue.transactions) != 4 || queue.submissions != 8 {
		t.Fatal("new branch retained stale staged markers")
	}
	var first types.Transaction
	if err := first.UnmarshalBinary(queue.transactions[0]); err != nil {
		t.Fatal(err)
	}
	if first.Nonce() != 9 {
		t.Fatal("new branch used old state nonce")
	}
}

func TestRestoreQueueRejectsWrongParentAndNonceGap(t *testing.T) {
	agent, queue := newStagingAgent(t, 5)
	agent.parentHash = common.HexToHash("0x999")
	if _, err := agent.restoreQueue(context.Background(), 12, 0); err == nil {
		t.Fatal("accepted stale parent")
	}
	agent.parentHash = queue.parent
	data := make([]byte, 36)
	binary.BigEndian.PutUint64(data[28:], 1)
	tx, err := types.SignTx(types.NewTransaction(1, agent.registry, new(big.Int), 100_000, big.NewInt(10), data), types.LatestSignerForChainID(agent.chainID), agent.key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()
	queue.transactions = []hexutil.Bytes{raw}
	if _, err := agent.restoreQueue(context.Background(), 12, 0); err == nil {
		t.Fatal("accepted non-contiguous queue")
	}
}

func TestRestoreQueueCountsApprovalNonceWithoutConsumingChallengeCapacity(t *testing.T) {
	agent, queue := newStagingAgent(t, 5)
	requestID := common.HexToHash("0x55")
	data, err := tpmregistry.PackRegistryCall("approveProducerSlot", requestID, uint64(10), common.HexToHash("0x66"), make([]byte, 65))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := types.SignTx(types.NewTransaction(7, agent.registry, new(big.Int), 100_000, big.NewInt(10), data), types.LatestSignerForChainID(agent.chainID), agent.key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	queue.transactions = []hexutil.Bytes{raw}
	nonce, err := agent.restoreQueue(context.Background(), 12, 7)
	if err != nil || nonce != 8 {
		t.Fatalf("approval nonce %d, err %v", nonce, err)
	}
	if _, ok := agent.staged["approval/"+requestID.String()+"/10/12"]; !ok {
		t.Fatal("approval was not restored")
	}
	if agent.queuedChallenges != 0 {
		t.Fatal("approval consumed challenge capacity")
	}
	if _, err := agent.stageChallenges(context.Background(), 12, nonce, big.NewInt(10)); err != nil {
		t.Fatal(err)
	}
	if len(queue.transactions) != 6 {
		t.Fatal("approval prevented five challenges")
	}
}
