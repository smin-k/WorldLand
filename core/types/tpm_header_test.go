package types

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/cryptoecc/WorldLand/rlp"
)

func TestTPMHeaderFieldsRLPRoundTrip(t *testing.T) {
	header := &Header{
		Difficulty:           big.NewInt(1),
		Number:               big.NewInt(2),
		BaseFee:              big.NewInt(3),
		Codeword:             []byte{1},
		CodeLength:           8,
		VRFProof:             []byte{2},
		VRFPublicKey:         []byte{3},
		EligibilityThreshold: big.NewInt(4),
		TPMDID:               bytes.Repeat([]byte{5}, 32),
		TPMWorkPublicKey:     bytes.Repeat([]byte{6}, 65),
		TPMWorkSignature:     bytes.Repeat([]byte{7}, 64),
	}
	encoded, err := rlp.EncodeToBytes(header)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Header
	if err := rlp.DecodeBytes(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.TPMDID, header.TPMDID) ||
		!bytes.Equal(decoded.TPMWorkPublicKey, header.TPMWorkPublicKey) ||
		!bytes.Equal(decoded.TPMWorkSignature, header.TPMWorkSignature) {
		t.Fatal("TPM header fields changed during RLP round trip")
	}
}
