package tpmregistry

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	ethereum "github.com/cryptoecc/WorldLand"
	"github.com/cryptoecc/WorldLand/accounts/abi"
	"github.com/cryptoecc/WorldLand/common"
)

const requestReaderABI = `[{"inputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"name":"requests","outputs":[{"internalType":"address","name":"controller","type":"address"},{"internalType":"uint64","name":"validatorEpoch","type":"uint64"},{"internalType":"uint64","name":"deadline","type":"uint64"},{"internalType":"bool","name":"finalized","type":"bool"},{"internalType":"bytes32","name":"statementHash","type":"bytes32"},{"internalType":"uint256","name":"collateral","type":"uint256"}],"stateMutability":"view","type":"function"}]`

type ContractCaller interface {
	CallContract(context.Context, ethereum.CallMsg, *big.Int) ([]byte, error)
	BlockNumber(context.Context) (uint64, error)
}

// RPCRequestVerifier checks the exact request frozen in canonical latest state.
type RPCRequestVerifier struct {
	client   ContractCaller
	registry common.Address
	abi      abi.ABI
}

func NewRPCRequestVerifier(client ContractCaller, registry common.Address) (*RPCRequestVerifier, error) {
	if client == nil || registry == (common.Address{}) {
		return nil, errors.New("tpmregistry: RPC client and registry are required")
	}
	parsed, err := abi.JSON(strings.NewReader(requestReaderABI))
	if err != nil {
		return nil, err
	}
	return &RPCRequestVerifier{client: client, registry: registry, abi: parsed}, nil
}

func (verifier *RPCRequestVerifier) VerifyRegistrationRequest(ctx context.Context, statement EnrollmentStatement) error {
	input, err := verifier.abi.Pack("requests", statement.RequestID)
	if err != nil {
		return err
	}
	output, err := verifier.client.CallContract(ctx, ethereum.CallMsg{To: &verifier.registry, Data: input}, nil)
	if err != nil {
		return err
	}
	values, err := verifier.abi.Unpack("requests", output)
	if err != nil {
		return err
	}
	if len(values) != 6 {
		return errors.New("tpmregistry: malformed requests response")
	}
	controller, ok := values[0].(common.Address)
	if !ok || controller == (common.Address{}) {
		return errors.New("tpmregistry: registration request does not exist")
	}
	epoch, ok := values[1].(uint64)
	if !ok {
		return errors.New("tpmregistry: malformed validator epoch")
	}
	deadline, ok := values[2].(uint64)
	if !ok {
		return errors.New("tpmregistry: malformed registration deadline")
	}
	finalized, ok := values[3].(bool)
	if !ok {
		return errors.New("tpmregistry: malformed finalized flag")
	}
	statementHash, ok := values[4].([32]byte)
	if !ok {
		return errors.New("tpmregistry: malformed statement hash")
	}
	if finalized {
		return errors.New("tpmregistry: registration request is already finalized")
	}
	if controller != statement.Controller || epoch != statement.ValidatorEpoch || deadline != statement.Deadline || common.Hash(statementHash) != statement.StructHash() {
		return errors.New("tpmregistry: on-chain request differs from enrollment statement")
	}
	blockNumber, err := verifier.client.BlockNumber(ctx)
	if err != nil {
		return err
	}
	if blockNumber > deadline {
		return fmt.Errorf("tpmregistry: registration request expired at block %d", deadline)
	}
	return nil
}
