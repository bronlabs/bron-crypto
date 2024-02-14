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
	expectedHex := "b4752959f476bb668a88a7239cae99d6bdc9f0add4523c01e8724d4dffdf5ac2"

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
	expectedHex := "a8d87ccb6aee6f5578080155895aa969ed14ff7aa5a8f534fdf65dac079123dd"

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

	expectedChlHex := "8eb0ae7f68452f2a81389b4fa6014162dd3221c0a02d9b0b2c8b94b0b4fb35eb"
	chlHex := hex.EncodeToString(chlBytes)

	if chlHex != expectedChlHex {
		t.Errorf("\nGot : %s\nWant: %s", chlHex, expectedChlHex)
	}
}
