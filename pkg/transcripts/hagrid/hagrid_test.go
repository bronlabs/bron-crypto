package hagrid_test

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/merlin"
)

func TestSimpleTranscript(t *testing.T) {
	mt := hagrid.NewTranscript("test protocol")
	mt.AppendMessages("some label", []byte("some data"))

	cBytes := mt.ExtractBytes("challenge", 32)
	cHex := fmt.Sprintf("%x", cBytes)
	expectedHex := "68da956bb56aa9f5f5e45dca75fc8216badde6a6a953c36db481f7faf8f21b2a"

	if cHex != expectedHex {
		t.Errorf("\nGot : %s\nWant: %s", cHex, expectedHex)
	}
}

func TestComplexTranscript(t *testing.T) {
	tr := hagrid.NewTranscript("test protocol")
	tr.AppendMessages("step1", []byte("some data"))

	data := make([]byte, 1024)
	for i := range data {
		data[i] = 99
	}

	var chlBytes []byte
	for i := 0; i < 32; i++ {
		chlBytes = tr.ExtractBytes("challenge", 32)
		tr.AppendMessages("bigdata", data)
		tr.AppendMessages("challengedata", chlBytes)
	}

	expectedChlHex := "db182e18df4d8dfde2facba6fe9d9de52e6fa3f740c2c3764b0de3022d50070d"
	chlHex := fmt.Sprintf("%x", chlBytes)

	if chlHex != expectedChlHex {
		t.Errorf("\nGot : %s\nWant: %s", chlHex, expectedChlHex)
	}
}

func TestTranscriptPRNG(t *testing.T) {
	label := "test protocol"
	t1 := hagrid.NewTranscript(label)
	t2 := hagrid.NewTranscript(label)
	t3 := hagrid.NewTranscript(label)
	t4 := hagrid.NewTranscript(label)

	comm1 := []byte("Commitment data 1")
	comm2 := []byte("Commitment data 2")

	witness1 := []byte("Witness data 1")
	witness2 := []byte("Witness data 2")

	// t1 will have commitment 1 and t2, t3, t4 will gave same commitment
	t1.AppendMessages("com", comm1)
	t2.AppendMessages("com", comm2)
	t3.AppendMessages("com", comm2)
	t4.AppendMessages("com", comm2)

	// t1, t2 will have same witness data
	// t3, t4 will have same witness data
	r1, err := t1.NewReader("witness", witness1, rand.New(rand.NewSource(0)))
	require.NoError(t, err)

	r2, err := t2.NewReader("witness", witness1, rand.New(rand.NewSource(0)))
	require.NoError(t, err)

	r3, err := t3.NewReader("witness", witness2, rand.New(rand.NewSource(0)))
	require.NoError(t, err)

	r4, err := t4.NewReader("witness", witness2, rand.New(rand.NewSource(0)))
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

func BenchmarkTranscript_AppendMessages(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping test in short mode.")
	}
	label := "test transcript"
	h := hagrid.NewTranscript(label)
	m := merlin.NewTranscript(label)
	b.Run("Hagrid", func(b *testing.B) {
		for n := 0; n <= b.N; n += 1 {
			for i := 0; i <= 10000; i += 1 {
				h.AppendMessages("step1", []byte(fmt.Sprintf("some data %d", i)))
			}
		}
	})
	b.Run("Merlin", func(b *testing.B) {
		for n := 0; n <= b.N; n += 1 {
			for i := 0; i <= 10000; i += 1 {
				m.AppendMessages("step1", []byte(fmt.Sprintf("some data %d", i)))
			}
		}
	})
}
