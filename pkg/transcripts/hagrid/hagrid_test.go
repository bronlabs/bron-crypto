package hagrid_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/hashing/tmmohash"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func TestSimpleTranscript(t *testing.T) {
	t.Parallel()
	mt := hagrid.NewTranscript("test protocol", nil)
	mt.AppendMessages("some label", []byte("some data"))

	cBytes, _ := mt.ExtractBytes("challenge", 32)
	cHex := hex.EncodeToString(cBytes)
	expectedHex := "24d665903e0d0cc2a28aa921f87953c4a6c1eae6ff4d3837c0a4a12eacccd14a"

	if cHex != expectedHex {
		t.Errorf("\nGot : %s\nWant: %s", cHex, expectedHex)
	}
}

func TestSimpleTranscriptWithPRNG(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

	expectedChlHex := "d09210cf6cf966acb4a75b556a09dd8ab8cebefdbfb5755903014cadef003152"
	chlHex := hex.EncodeToString(chlBytes)

	if chlHex != expectedChlHex {
		t.Errorf("\nGot : %s\nWant: %s", chlHex, expectedChlHex)
	}
}
