package tpmproducer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	ethereum "github.com/cryptoecc/WorldLand"
	"github.com/cryptoecc/WorldLand/accounts/abi"
	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/common/hexutil"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/ethclient"
	"github.com/cryptoecc/WorldLand/rpc"
)

type repeatedFlag []string

func (values *repeatedFlag) String() string { return strings.Join(*values, ",") }
func (values *repeatedFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type trackedRequest struct {
	event    tpmregistry.ProducerRegistrationEvent
	evidence *tpmregistry.Evidence
	state    tpmregistry.ProducerRequestState
}

type producerAgent struct {
	chainID          *big.Int
	registry         common.Address
	key              *ecdsa.PrivateKey
	address          common.Address
	policy           *tpmregistry.Policy
	policyHash       common.Hash
	client           producerChain
	rpc              rpcCaller
	contract         producerRegistry
	lookback         uint64
	maxPerSlot       int
	gasLimit         uint64
	requests         map[common.Hash]*trackedRequest
	staged           map[string]struct{}
	parentHash       common.Hash
	queuedChallenges int
}

type producerChain interface {
	ChainID(context.Context) (*big.Int, error)
	HeaderByNumber(context.Context, *big.Int) (*types.Header, error)
	NonceAt(context.Context, common.Address, *big.Int) (uint64, error)
	PendingNonceAt(context.Context, common.Address) (uint64, error)
	SuggestGasPrice(context.Context) (*big.Int, error)
	FilterLogs(context.Context, ethereum.FilterQuery) ([]types.Log, error)
}

type producerRegistry interface {
	Request(context.Context, common.Hash) (tpmregistry.RegistrationRequestState, error)
	ProducerRequest(context.Context, common.Hash) (tpmregistry.ProducerRequestState, error)
	ProducerRequestPolicyDigest(context.Context, common.Hash) (common.Hash, error)
	ProducerSlot(context.Context, common.Hash, uint64) (tpmregistry.ProducerSlotState, error)
}

type rpcCaller interface {
	CallContext(context.Context, interface{}, string, ...interface{}) error
}

type enrollmentQueue struct {
	ParentHash   common.Hash     `json:"parentHash"`
	Target       hexutil.Uint64  `json:"target"`
	Transactions []hexutil.Bytes `json:"transactions"`
}

func Main() {
	var roots repeatedFlag
	var profiles repeatedFlag
	rpcURL := flag.String("rpc", "http://127.0.0.1:8545", "local WorldLand JSON-RPC URL with private miner API")
	registryHex := flag.String("registry", tpmregistry.DefaultRegistryAddress.Hex(), "registry address")
	chainIDValue := flag.Int64("chain-id", 0, "chain ID")
	keyFile := flag.String("producer-key", "", "coinbase secp256k1 private-key file")
	requireEKOID := flag.Bool("require-ek-oid", true, "require tcg-kp-EKCertificate extended key usage")
	certificateProfile := flag.String("certificate-profile", tpmregistry.CertificateProfileManufacturer, "EK certificate policy: manufacturer or gcp-cas-v1 (pinned Google root)")
	maxEvidence := flag.Uint64("max-evidence-bytes", 1024*1024, "maximum canonical evidence size")
	lookback := flag.Uint64("lookback", 512, "blocks scanned for live registration requests")
	maxPerSlot := flag.Int("max-per-slot", 4, "maximum registration challenges included per block")
	gasLimit := flag.Uint64("challenge-gas", 1200000, "gas limit for each private challenge transaction")
	poll := flag.Duration("poll", 500*time.Millisecond, "canonical head polling interval")
	flag.Var(&roots, "ek-root", "trusted EK root certificate PEM/DER (repeatable)")
	flag.Var(&profiles, "profile-hash", "allowed 32-byte profile hash (repeatable)")
	flag.Parse()

	if *chainIDValue <= 0 || *keyFile == "" || !common.IsHexAddress(*registryHex) || *maxPerSlot <= 0 {
		flag.Usage()
		log.Fatal("chain-id, producer-key, registry and positive max-per-slot are required")
	}
	certificates, err := loadCertificates(roots)
	if err != nil {
		log.Fatal(err)
	}
	allowedProfiles := make([]common.Hash, len(profiles))
	for i, value := range profiles {
		decoded, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
		if err != nil || len(decoded) != common.HashLength {
			log.Fatalf("invalid profile hash %q", value)
		}
		allowedProfiles[i] = common.BytesToHash(decoded)
	}
	policy := &tpmregistry.Policy{
		Version: tpmregistry.EvidenceVersion, RootCertificates: certificates,
		RequireEKCertificateOID: *requireEKOID, MaxEvidenceBytes: *maxEvidence,
		AllowedProfileHashes: allowedProfiles,
	}
	if err := policy.ConfigureCertificateProfile(*certificateProfile); err != nil {
		log.Fatal(err)
	}
	policyHash, err := policy.Digest()
	if err != nil {
		log.Fatal(err)
	}
	key, err := readPrivateKey(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	client, err := ethclient.Dial(*rpcURL)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	rpcClient, err := rpc.Dial(*rpcURL)
	if err != nil {
		log.Fatal(err)
	}
	defer rpcClient.Close()
	contract, err := tpmregistry.NewRegistryClient(common.HexToAddress(*registryHex), client)
	if err != nil {
		log.Fatal(err)
	}
	agent := &producerAgent{
		chainID: big.NewInt(*chainIDValue), registry: common.HexToAddress(*registryHex),
		key: key, address: crypto.PubkeyToAddress(key.PublicKey), policy: policy, policyHash: policyHash,
		client: client, rpc: rpcClient, contract: contract, lookback: *lookback,
		maxPerSlot: *maxPerSlot, gasLimit: *gasLimit,
		requests: make(map[common.Hash]*trackedRequest), staged: make(map[string]struct{}),
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := agent.verifyNetwork(ctx); err != nil {
		log.Fatal(err)
	}
	log.Printf("TGPoW producer %s started (policy %s)", agent.address, agent.policyHash)
	ticker := time.NewTicker(*poll)
	defer ticker.Stop()
	for {
		if err := agent.tick(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("producer tick failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (agent *producerAgent) verifyNetwork(ctx context.Context) error {
	chainID, err := agent.client.ChainID(ctx)
	if err != nil {
		return err
	}
	if chainID.Cmp(agent.chainID) != 0 {
		return fmt.Errorf("configured chain ID %s != RPC chain ID %s", agent.chainID, chainID)
	}
	var coinbase common.Address
	if err := agent.rpc.CallContext(ctx, &coinbase, "eth_coinbase"); err != nil {
		return err
	}
	if coinbase != agent.address {
		return fmt.Errorf("producer key %s != node coinbase %s", agent.address, coinbase)
	}
	return nil
}

func (agent *producerAgent) tick(ctx context.Context) error {
	header, err := agent.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return err
	}
	return agent.prepareHeader(ctx, header)
}

func (agent *producerAgent) prepareHeader(ctx context.Context, header *types.Header) error {
	if header == nil || header.Number == nil {
		return errors.New("producer: canonical head is unavailable")
	}
	head := header.Number.Uint64()
	agent.parentHash = header.Hash()
	if err := agent.discoverRequests(ctx, head); err != nil {
		return err
	}
	stateNonce, err := agent.client.NonceAt(ctx, agent.address, header.Number)
	if err != nil {
		return err
	}
	pendingNonce, err := agent.client.PendingNonceAt(ctx, agent.address)
	if err != nil {
		return err
	}
	if pendingNonce != stateNonce {
		return fmt.Errorf("coinbase has pending transactions (state nonce %d, pending %d)", stateNonce, pendingNonce)
	}
	gasPrice, err := agent.client.SuggestGasPrice(ctx)
	if err != nil {
		return err
	}
	target := head + 1
	// Recover reservations from the miner, including a prior process's queue or
	// a transaction accepted before its RPC acknowledgement was lost.
	nonce, err := agent.restoreQueue(ctx, target, stateNonce)
	if err != nil {
		return err
	}
	nextNonce, err := agent.stageApprovals(ctx, head, target, nonce, gasPrice)
	if err != nil {
		return err
	}
	_, err = agent.stageChallenges(ctx, target, nextNonce, gasPrice)
	return err
}

func (agent *producerAgent) discoverRequests(ctx context.Context, head uint64) error {
	from := uint64(0)
	if head > agent.lookback {
		from = head - agent.lookback
	}
	entries, err := agent.client.FilterLogs(ctx, ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(from), ToBlock: new(big.Int).SetUint64(head),
		Addresses: []common.Address{agent.registry},
		Topics:    [][]common.Hash{{tpmregistry.ProducerEventTopic("ProducerRegistrationRequested")}},
	})
	if err != nil {
		return err
	}
	canonicalRequests := make(map[common.Hash]*trackedRequest)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Bound decoding work before allocating a canonical evidence bundle.
		if uint64(len(entry.Data)) > agent.policy.MaxEvidenceBytes+1024 {
			continue
		}
		event, err := tpmregistry.ParseProducerRegistrationEvent(entry)
		if err != nil || event.Removed || head > event.ResponseDeadline {
			continue
		}
		evidence, err := tpmregistry.DecodeEvidence(event.EvidenceBundle)
		if err != nil {
			log.Printf("reject request %s: decode evidence: %v", event.RequestID, err)
			continue
		}
		validated, err := agent.policy.ValidateEvidence(agent.chainID, agent.registry, evidence)
		if err != nil {
			log.Printf("reject request %s: validate evidence: %v", event.RequestID, err)
			continue
		}
		request, err := agent.contract.Request(ctx, event.RequestID)
		if err != nil {
			return err
		}
		if request.Finalized || request.ValidatorEpoch != 0 {
			continue
		}
		producerState, err := agent.contract.ProducerRequest(ctx, event.RequestID)
		if err != nil {
			return err
		}
		requestPolicy, err := agent.contract.ProducerRequestPolicyDigest(ctx, event.RequestID)
		if err != nil {
			return err
		}
		if requestPolicy != agent.policyHash {
			log.Printf("reject request %s: producer policy %s != local %s", event.RequestID, requestPolicy, agent.policyHash)
			continue
		}
		statement := tpmregistry.ProducerEnrollmentStatement{
			RequestID: event.RequestID, Identity: event.Identity, Controller: event.Controller,
			WorkKeyHash: validated.WorkKeyHash, VRFKeyHash: validated.VRFKeyHash,
			ProfileHash: validated.ProfileHash, DeviceNullifier: validated.DeviceNullifier,
			PolicyDigest: requestPolicy, EvidenceHash: validated.EvidenceHash,
			FirstSlot: producerState.FirstSlot, LastSlot: producerState.LastSlot,
			ResponseDeadline: producerState.ResponseDeadline,
		}
		if event.Identity != validated.DID || statement.StructHash() != request.StatementHash ||
			request.StatementHash != event.StatementHash || request.Controller != event.Controller {
			log.Printf("reject request %s: statement mismatch", event.RequestID)
			continue
		}
		canonicalRequests[event.RequestID] = &trackedRequest{event: event, evidence: evidence, state: producerState}
		if _, exists := agent.requests[event.RequestID]; !exists {
			log.Printf("tracking request %s slots %d-%d", event.RequestID, producerState.FirstSlot, producerState.LastSlot)
		}
	}
	agent.requests = canonicalRequests
	return nil
}

func (agent *producerAgent) stageChallenges(ctx context.Context, target, nonce uint64, gasPrice *big.Int) (uint64, error) {
	for _, requestID := range agent.sortedRequestIDs() {
		if err := ctx.Err(); err != nil {
			return nonce, err
		}
		tracked := agent.requests[requestID]
		if target < tracked.state.FirstSlot || target > tracked.state.LastSlot {
			continue
		}
		key := fmt.Sprintf("%s/%d", requestID, target)
		if _, exists := agent.staged[key]; exists {
			continue
		}
		if agent.queuedChallenges >= agent.maxPerSlot {
			log.Printf("challenge capacity %d reached at slot %d; request %s remains unstaged (n-of-n enrollment can expire if any slot is missed)", agent.maxPerSlot, target, requestID)
			continue
		}
		slot, err := agent.contract.ProducerSlot(ctx, requestID, target)
		if err != nil {
			return nonce, err
		}
		if slot.Producer != (common.Address{}) {
			continue
		}
		secretBytes := make([]byte, common.HashLength)
		if _, err := rand.Read(secretBytes); err != nil {
			return nonce, err
		}
		secret := common.BytesToHash(secretBytes)
		credentialBlob, encryptedSecret, err := tpmregistry.MakeCredential(tracked.evidence, secretBytes)
		if err != nil {
			return nonce, err
		}
		credentialHash, err := tpmregistry.CredentialHash(credentialBlob, encryptedSecret)
		if err != nil {
			return nonce, err
		}
		commitment := tpmregistry.ProducerChallengeCommitment(
			agent.chainID, agent.registry, requestID, tracked.event.StatementHash,
			target, agent.address, credentialHash, secret,
		)
		digest := tpmregistry.ProducerChallengeDigest(
			agent.chainID, agent.registry, requestID, target, agent.address, credentialHash, commitment,
		)
		producerSignature, err := crypto.Sign(digest[:], agent.key)
		if err != nil {
			return nonce, err
		}
		callData, err := tpmregistry.PackRegistryCall(
			"publishProducerChallenge", requestID, credentialBlob, encryptedSecret, commitment, producerSignature,
		)
		if err != nil {
			return nonce, err
		}
		unsigned := types.NewTransaction(nonce, agent.registry, new(big.Int), agent.gasLimit, gasPrice, callData)
		transaction, err := types.SignTx(unsigned, types.LatestSignerForChainID(agent.chainID), agent.key)
		if err != nil {
			return nonce, err
		}
		accepted, err := agent.stagePrivateTransaction(ctx, target, transaction)
		if err != nil {
			return nonce, fmt.Errorf("stage request %s slot %d: %w", requestID, target, err)
		}
		agent.staged[key] = struct{}{}
		nonce++
		agent.queuedChallenges++
		log.Printf("staged private challenge %s for request %s slot %d", accepted, requestID, target)
	}
	return nonce, nil
}

func (agent *producerAgent) stageApprovals(ctx context.Context, head, target, nonce uint64, gasPrice *big.Int) (uint64, error) {
	count := len(agent.staged) - agent.queuedChallenges
	for _, requestID := range agent.sortedRequestIDs() {
		if err := ctx.Err(); err != nil {
			return nonce, err
		}
		tracked := agent.requests[requestID]
		if head < tracked.state.FirstSlot || head > tracked.state.ResponseDeadline {
			continue
		}
		entries, err := agent.client.FilterLogs(ctx, ethereum.FilterQuery{
			FromBlock: new(big.Int).SetUint64(tracked.state.FirstSlot), ToBlock: new(big.Int).SetUint64(head),
			Addresses: []common.Address{agent.registry},
			Topics: [][]common.Hash{
				{tpmregistry.ProducerEventTopic("ProducerResponseSubmitted")}, {requestID},
			},
		})
		if err != nil {
			return nonce, err
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return nonce, err
			}
			if count >= agent.maxPerSlot*6 {
				return nonce, nil
			}
			if uint64(len(entry.Data)) > agent.policy.MaxEvidenceBytes+1024 {
				continue
			}
			response, err := tpmregistry.ParseProducerResponseEvent(entry)
			if err != nil || response.Removed || tpmregistry.ProducerEvidenceHash(response.EvidenceBundle) != response.EvidenceHash {
				continue
			}
			slot, err := agent.contract.ProducerSlot(ctx, requestID, response.Slot)
			if err != nil {
				return nonce, err
			}
			if slot.Producer != agent.address || slot.Approved || !slot.Responded || slot.EvidenceHash != response.EvidenceHash {
				continue
			}
			challenge := tpmregistry.ProducerCertifyChallenge(
				agent.chainID, agent.registry, requestID, response.Slot, slot.Commitment,
			)
			if err := tpmregistry.VerifyProducerResponseEvidence(tracked.evidence, challenge[:], response.EvidenceBundle); err != nil {
				log.Printf("reject response request %s slot %d: %v", requestID, response.Slot, err)
				continue
			}
			if researchWithholdApproval(agent.chainID, tracked.event.Identity, response.Slot, tracked.state.FirstSlot) {
				log.Printf("RESEARCH withheld verified approval request %s slot %d", requestID, response.Slot)
				continue
			}
			digest := tpmregistry.ProducerApprovalDigest(
				agent.chainID, agent.registry, requestID, response.Slot, slot.Commitment,
				response.EvidenceHash, tracked.event.Identity, tracked.state.ResponseDeadline,
			)
			signature, err := crypto.Sign(digest[:], agent.key)
			if err != nil {
				return nonce, err
			}
			stagedKey := fmt.Sprintf("approval/%s/%d/%d", requestID, response.Slot, target)
			if _, exists := agent.staged[stagedKey]; exists {
				continue
			}
			callData, err := tpmregistry.PackRegistryCall(
				"approveProducerSlot", requestID, response.Slot, tracked.event.Identity, signature,
			)
			if err != nil {
				return nonce, err
			}
			unsigned := types.NewTransaction(nonce, agent.registry, new(big.Int), agent.gasLimit, gasPrice, callData)
			transaction, err := types.SignTx(unsigned, types.LatestSignerForChainID(agent.chainID), agent.key)
			if err != nil {
				return nonce, err
			}
			accepted, err := agent.stagePrivateTransaction(ctx, target, transaction)
			if err != nil {
				return nonce, err
			}
			agent.staged[stagedKey] = struct{}{}
			nonce++
			count++
			log.Printf("staged private approval %s for request %s slot %d", accepted, requestID, response.Slot)
		}
	}
	return nonce, nil
}

func (agent *producerAgent) stagePrivateTransaction(ctx context.Context, target uint64, transaction *types.Transaction) (common.Hash, error) {
	raw, err := transaction.MarshalBinary()
	if err != nil {
		return common.Hash{}, err
	}
	var accepted common.Hash
	err = agent.rpc.CallContext(
		ctx, &accepted, "miner_submitEnrollmentTransaction", hexutil.Uint64(target), hexutil.Bytes(raw), agent.parentHash,
	)
	if err == nil && accepted != transaction.Hash() {
		return common.Hash{}, errors.New("producer: miner acknowledged a different transaction hash")
	}
	return accepted, err
}

func (agent *producerAgent) sortedRequestIDs() []common.Hash {
	ids := make([]common.Hash, 0, len(agent.requests))
	for id := range agent.requests {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	return ids
}

func (agent *producerAgent) restoreQueue(ctx context.Context, target, stateNonce uint64) (uint64, error) {
	var queue enrollmentQueue
	if err := agent.rpc.CallContext(ctx, &queue, "miner_enrollmentQueue", hexutil.Uint64(target), agent.parentHash); err != nil {
		return stateNonce, fmt.Errorf("producer: read branch-bound enrollment queue: %w", err)
	}
	if queue.ParentHash != agent.parentHash || uint64(queue.Target) != target {
		return stateNonce, errors.New("producer: enrollment queue belongs to a different parent")
	}
	parsed, err := abi.JSON(strings.NewReader(tpmregistry.RegistryABI))
	if err != nil {
		return stateNonce, err
	}
	transactions := make([]*types.Transaction, 0, len(queue.Transactions))
	for _, raw := range queue.Transactions {
		var tx types.Transaction
		if err := tx.UnmarshalBinary(raw); err != nil {
			return stateNonce, err
		}
		transactions = append(transactions, &tx)
	}
	sort.Slice(transactions, func(i, j int) bool { return transactions[i].Nonce() < transactions[j].Nonce() })
	staged := make(map[string]struct{})
	challenges := 0
	nonce := stateNonce
	for _, tx := range transactions {
		if tx.Nonce() != nonce || tx.To() == nil || *tx.To() != agent.registry {
			return stateNonce, errors.New("producer: private queue has a nonce gap or unexpected destination")
		}
		sender, err := types.Sender(types.LatestSignerForChainID(agent.chainID), tx)
		if err != nil || sender != agent.address {
			return stateNonce, errors.New("producer: private queue contains a different sender")
		}
		if len(tx.Data()) < 4 {
			return stateNonce, errors.New("producer: malformed private transaction")
		}
		method, err := parsed.MethodById(tx.Data()[:4])
		if err != nil {
			return stateNonce, err
		}
		values, err := method.Inputs.Unpack(tx.Data()[4:])
		if err != nil || len(values) == 0 {
			return stateNonce, errors.New("producer: malformed enrollment calldata")
		}
		requestID, ok := values[0].([32]byte)
		if !ok {
			return stateNonce, errors.New("producer: malformed enrollment request ID")
		}
		switch method.Name {
		case "publishProducerChallenge":
			staged[fmt.Sprintf("%s/%d", common.Hash(requestID), target)] = struct{}{}
			challenges++
		case "approveProducerSlot":
			slot, ok := values[1].(uint64)
			if !ok {
				return stateNonce, errors.New("producer: malformed approval slot")
			}
			staged[fmt.Sprintf("approval/%s/%d/%d", common.Hash(requestID), slot, target)] = struct{}{}
		default:
			return stateNonce, errors.New("producer: unexpected enrollment method")
		}
		nonce++
	}
	agent.staged, agent.queuedChallenges = staged, challenges
	return nonce, nil
}

func readPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return crypto.HexToECDSA(strings.TrimPrefix(strings.TrimSpace(string(encoded)), "0x"))
}

func loadCertificates(paths []string) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	for _, path := range paths {
		encoded, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		remaining := encoded
		foundPEM := false
		for {
			block, rest := pem.Decode(remaining)
			if block == nil {
				break
			}
			remaining = rest
			if block.Type != "CERTIFICATE" {
				continue
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
			certificates = append(certificates, certificate)
			foundPEM = true
		}
		if !foundPEM {
			certificate, err := x509.ParseCertificate(encoded)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
			certificates = append(certificates, certificate)
		}
	}
	return certificates, nil
}
