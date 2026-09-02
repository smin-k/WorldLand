package ethapi

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/common/hexutil"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
)

func TestRPCMarshalHeaderIncludesTPMEvidence(t *testing.T) {
	header := &types.Header{
		Number:           big.NewInt(1),
		Difficulty:       big.NewInt(65_536),
		TPMDID:           bytes.Repeat([]byte{1}, common.HashLength),
		TPMWorkPublicKey: append([]byte{4}, bytes.Repeat([]byte{2}, tpmwork.PublicKeySize-1)...),
		TPMWorkSignature: bytes.Repeat([]byte{3}, tpmwork.SignatureSize),
	}
	result := RPCMarshalHeader(header)
	for name, want := range map[string][]byte{
		"tpmDID": header.TPMDID, "tpmWorkPublicKey": header.TPMWorkPublicKey, "tpmWorkSignature": header.TPMWorkSignature,
	} {
		got, ok := result[name].(hexutil.Bytes)
		if !ok || !bytes.Equal(got, want) {
			t.Fatalf("%s = %#v, want %x", name, result[name], want)
		}
	}
}
