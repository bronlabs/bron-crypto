package merlin_test

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/transcripts/merlin"
)

func TestSimpleTranscript(t *testing.T) {
	mt := merlin.NewTranscript("test protocol")
	mt.AppendMessage([]byte("some label"), []byte("some data"))

	cBytes := mt.ExtractBytes([]byte("challenge"), 32)
	cHex := fmt.Sprintf("%x", cBytes)
	expectedHex := "aa57b4786a83baba7ed4ad21ac2fa9a76542358b32cd0eac24b05ea353f1d9b2"

	if cHex != expectedHex {
		t.Errorf("\nGot : %s\nWant: %s", cHex, expectedHex)
	}
}

func TestComplexTranscript(t *testing.T) {
	tr := merlin.NewTranscript("test protocol")
	tr.AppendMessage([]byte("step1"), []byte("some data"))

	data := make([]byte, 1024)
	for i := range data {
		data[i] = 99
	}

	var chlBytes []byte
	for i := 0; i < 32; i++ {
		chlBytes = tr.ExtractBytes([]byte("challenge"), 32)
		tr.AppendMessage([]byte("bigdata"), data)
		tr.AppendMessage([]byte("challengedata"), chlBytes)
	}

	expectedChlHex := "30bce6b150411d5ad51dd231a2d96d1ea886664e58e09dd7a5730a09f554a7d4"
	chlHex := fmt.Sprintf("%x", chlBytes)

	if chlHex != expectedChlHex {
		t.Errorf("\nGot : %s\nWant: %s", chlHex, expectedChlHex)
	}
}

func TestTranscriptPRNG(t *testing.T) {
	label := "test protocol"
	t1 := merlin.NewTranscript(label)
	t2 := merlin.NewTranscript(label)
	t3 := merlin.NewTranscript(label)
	t4 := merlin.NewTranscript(label)

	comm1 := []byte("Commitment data 1")
	comm2 := []byte("Commitment data 2")

	witness1 := []byte("Witness data 1")
	witness2 := []byte("Witness data 2")

	// t1 will have commitment 1 and t2, t3, t4 will gave same commitment
	t1.AppendMessage([]byte("com"), comm1)
	t2.AppendMessage([]byte("com"), comm2)
	t3.AppendMessage([]byte("com"), comm2)
	t4.AppendMessage([]byte("com"), comm2)

	// t1, t2 will have same witness data
	// t3, t4 will have same witness data
	r1, err := t1.NewReader([]byte("witness"), witness1, rand.New(rand.NewSource(0)))
	require.NoError(t, err)

	r2, err := t2.NewReader([]byte("witness"), witness1, rand.New(rand.NewSource(0)))
	require.NoError(t, err)

	r3, err := t3.NewReader([]byte("witness"), witness2, rand.New(rand.NewSource(0)))
	require.NoError(t, err)

	r4, err := t4.NewReader([]byte("witness"), witness2, rand.New(rand.NewSource(0)))
	require.NoError(t, err)
	var (
		s1 = make([]byte, 32)
		s2 = make([]byte, 32)
		s3 = make([]byte, 32)
		s4 = make([]byte, 32)
	)

	n, err := r1.Read(s1)
	require.NoError(t, err)
	require.Equal(t, n, 32)

	n, err = r2.Read(s2)
	require.NoError(t, err)
	require.Equal(t, n, 32)

	n, err = r3.Read(s3)
	require.NoError(t, err)
	require.Equal(t, n, 32)

	n, err = r4.Read(s4)
	require.NoError(t, err)
	require.Equal(t, n, 32)

	// s1 shouldn't match with any due to different commitment data
	// s2 shouldn't match with any due to different witness data
	// s3 and s4 match since they same same commitment and witness data, given a bad rng.
	// this says that above no equalities are due to different commitments and witness but not because of RNG
	require.NotEqual(t, s1, s2)
	require.NotEqual(t, s1, s3)
	require.NotEqual(t, s1, s4)

	require.NotEqual(t, s2, s3)
	require.NotEqual(t, s2, s4)

	require.Equal(t, s3, s4)
}
