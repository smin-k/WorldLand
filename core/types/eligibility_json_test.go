package types

import (
	"encoding/json"
	"math/big"
	"testing"
)

func TestHeaderEligibilityJSONRoundTrip(t *testing.T) {
	max := new(big.Int).Lsh(big.NewInt(1), 256)
	for _, value := range []*big.Int{nil, big.NewInt(0), big.NewInt(256), new(big.Int).Sub(new(big.Int).Set(max), big.NewInt(1)), max} {
		h := &Header{Difficulty: big.NewInt(65536), Number: big.NewInt(7), Extra: []byte{}, EligibilityThreshold: value, TPMWorkSignature: []byte{1}}
		encoded, err := json.Marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		var got Header
		if err := json.Unmarshal(encoded, &got); err != nil {
			t.Fatalf("threshold %v: %v", value, err)
		}
		if (value == nil) != (got.EligibilityThreshold == nil) || value != nil && value.Cmp(got.EligibilityThreshold) != 0 {
			t.Fatalf("threshold changed: %v -> %v", value, got.EligibilityThreshold)
		}
		if h.Hash() != got.Hash() {
			t.Fatalf("JSON round trip changed consensus header hash for threshold %v", value)
		}
	}
}

func TestEligibilityJSONRejectsInvalidValues(t *testing.T) {
	for _, input := range []string{`123`, `"0x"`, `"0x00"`, `"-0x1"`, `"100"`, `"0xg"`, `"0x10000000000000000000000000000000000000000000000000000000000000001"`, `"0x20000000000000000000000000000000000000000000000000000000000000000"`} {
		var v eligibilityThresholdJSON
		if err := json.Unmarshal([]byte(input), &v); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	for _, value := range []*big.Int{big.NewInt(-1), new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))} {
		if _, err := json.Marshal((*eligibilityThresholdJSON)(value)); err == nil {
			t.Fatalf("marshaled invalid threshold %v", value)
		}
	}
}

func TestHeaderOtherQuantitiesRemainUint256(t *testing.T) {
	h := &Header{Difficulty: big.NewInt(65536), Number: big.NewInt(7), Extra: []byte{}}
	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"difficulty", "number", "baseFeePerGas"} {
		var fields map[string]interface{}
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		fields[field] = allEligibleHex
		encoded, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		var got Header
		if err := json.Unmarshal(encoded, &got); err == nil {
			t.Fatalf("accepted oversized %s", field)
		}
	}
}
