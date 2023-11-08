package hagrid_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/hashing/tmmohash"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

func TestSimpleTranscript(t *testing.T) {
	mt := hagrid.NewTranscript("test protocol", nil)
	mt.AppendMessages("some label", []byte("some data"))

	cBytes, _ := mt.ExtractBytes("challenge", 32)
	cHex := hex.EncodeToString(cBytes)
	expectedHex := "d0b97977f3e37ad374982b0fddafc450d6ccdf8dcda6c4eb3fef4439eae971bb"

	if cHex != expectedHex {
		t.Errorf("\nGot : %s\nWant: %s", cHex, expectedHex)
	}
}

func TestSimpleTranscriptWithPRNG(t *testing.T) {
	prng, err := tmmohash.NewTmmoPrng(32, 256, nil, []byte("test protocol"))
	require.NoError(t, err)
	mt := hagrid.NewTranscript("test protocol", prng)
	mt.AppendMessages("some label", []byte("some data"))

	cBytes, _ := mt.ExtractBytes("challenge", 32)
	cHex := hex.EncodeToString(cBytes)
	expectedHex := "af66587a9cd4f0c37e0bbd319380886ba827b7c7face3a29e30b295a7fd8cc5e"

	if cHex != expectedHex {
		t.Errorf("\nGot : %s\nWant: %s", cHex, expectedHex)
	}
}

func TestComplexTranscript(t *testing.T) {
	tr := hagrid.NewTranscript("test protocol", nil)
	tr.AppendMessages("step1", []byte("some data"))

	data := make([]byte, 1024)
	for i := range data {
		data[i] = 99
	}

	var chlBytes []byte
	for i := 0; i < 32; i++ {
		chlBytes, _ = tr.ExtractBytes("challenge", 32)
		tr.AppendMessages("bigdata", data)
		tr.AppendMessages("challengedata", chlBytes)
	}

	expectedChlHex := "4e3888588ba577a20a94550e81e5affe9c0e82b246b1c90fcb996f636bccf057"
	chlHex := hex.EncodeToString(chlBytes)

	if chlHex != expectedChlHex {
		t.Errorf("\nGot : %s\nWant: %s", chlHex, expectedChlHex)
	}
}
