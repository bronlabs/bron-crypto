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
	expectedHex := "36e5c27c9fb496cb398e3cd11e41cf54973cb17c854dacfc7f1c62d207e27e7b"

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
	expectedHex := "38a99bc5802f931b57bc471b13359cd6d385e882804d9f9a8d96f51333fd33a6"

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

	expectedChlHex := "4b9293b6ceb652ec9e9cf33429add29a537781a59918d2820135770238b466b6"
	chlHex := hex.EncodeToString(chlBytes)

	if chlHex != expectedChlHex {
		t.Errorf("\nGot : %s\nWant: %s", chlHex, expectedChlHex)
	}
}
