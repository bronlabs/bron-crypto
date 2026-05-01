package hash_comm_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

// badReader is an io.Reader that always fails.
type badReader struct{}

func (badReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

// shortReader returns at most n bytes total before EOF.
type shortReader struct{ remaining int }

func (r *shortReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := min(len(p), r.remaining)
	for i := range n {
		p[i] = 0xAB
	}
	r.remaining -= n
	return n, nil
}

func TestNewCommitment(t *testing.T) {
	t.Parallel()

	t.Run("nil input rejected", func(t *testing.T) {
		t.Parallel()
		c, err := hash_comm.NewCommitment(nil)
		require.Error(t, err)
		require.Equal(t, hash_comm.Commitment{}, c)
	})

	t.Run("empty input rejected", func(t *testing.T) {
		t.Parallel()
		c, err := hash_comm.NewCommitment([]byte{})
		require.Error(t, err)
		require.Equal(t, hash_comm.Commitment{}, c)
	})

	t.Run("too short rejected", func(t *testing.T) {
		t.Parallel()
		c, err := hash_comm.NewCommitment(bytes.Repeat([]byte{0xAB}, hash_comm.DigestSize-1))
		require.Error(t, err)
		require.Equal(t, hash_comm.Commitment{}, c)
	})

	t.Run("too long rejected", func(t *testing.T) {
		t.Parallel()
		c, err := hash_comm.NewCommitment(bytes.Repeat([]byte{0xAB}, hash_comm.DigestSize+1))
		require.Error(t, err)
		require.Equal(t, hash_comm.Commitment{}, c)
	})

	t.Run("exact length succeeds and copies contents", func(t *testing.T) {
		t.Parallel()
		in := bytes.Repeat([]byte{0xAB}, hash_comm.DigestSize)
		c, err := hash_comm.NewCommitment(in)
		require.NoError(t, err)
		require.Equal(t, in, c[:])
	})

	t.Run("input mutation does not affect commitment", func(t *testing.T) {
		t.Parallel()
		in := bytes.Repeat([]byte{0xAB}, hash_comm.DigestSize)
		c, err := hash_comm.NewCommitment(in)
		require.NoError(t, err)

		in[0] ^= 0xFF
		require.Equal(t, byte(0xAB), c[0])
	})
}

func TestNewWitness(t *testing.T) {
	t.Parallel()

	t.Run("nil input rejected", func(t *testing.T) {
		t.Parallel()
		w, err := hash_comm.NewWitness(nil)
		require.Error(t, err)
		require.Equal(t, hash_comm.Witness{}, w)
	})

	t.Run("empty input rejected", func(t *testing.T) {
		t.Parallel()
		w, err := hash_comm.NewWitness([]byte{})
		require.Error(t, err)
		require.Equal(t, hash_comm.Witness{}, w)
	})

	t.Run("too short rejected", func(t *testing.T) {
		t.Parallel()
		w, err := hash_comm.NewWitness(bytes.Repeat([]byte{0xCD}, hash_comm.DigestSize-1))
		require.Error(t, err)
		require.Equal(t, hash_comm.Witness{}, w)
	})

	t.Run("too long rejected", func(t *testing.T) {
		t.Parallel()
		w, err := hash_comm.NewWitness(bytes.Repeat([]byte{0xCD}, hash_comm.DigestSize+1))
		require.Error(t, err)
		require.Equal(t, hash_comm.Witness{}, w)
	})

	t.Run("exact length succeeds and copies contents", func(t *testing.T) {
		t.Parallel()
		in := bytes.Repeat([]byte{0xCD}, hash_comm.DigestSize)
		w, err := hash_comm.NewWitness(in)
		require.NoError(t, err)
		require.Equal(t, in, w[:])
	})

	t.Run("input mutation does not affect witness", func(t *testing.T) {
		t.Parallel()
		in := bytes.Repeat([]byte{0xCD}, hash_comm.DigestSize)
		w, err := hash_comm.NewWitness(in)
		require.NoError(t, err)

		in[0] ^= 0xFF
		require.Equal(t, byte(0xCD), w[0])
	})
}

func TestSampleCommitmentKey(t *testing.T) {
	t.Parallel()

	t.Run("nil prng", func(t *testing.T) {
		t.Parallel()
		k, err := hash_comm.SampleCommitmentKey(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "nil")
		require.Equal(t, hash_comm.CommitmentKey{}, k)
	})

	t.Run("failing reader", func(t *testing.T) {
		t.Parallel()
		k, err := hash_comm.SampleCommitmentKey(badReader{})
		require.Error(t, err)
		require.Equal(t, hash_comm.CommitmentKey{}, k)
	})

	t.Run("short reader", func(t *testing.T) {
		t.Parallel()
		k, err := hash_comm.SampleCommitmentKey(&shortReader{remaining: hash_comm.KeySize - 1})
		require.Error(t, err)
		require.Equal(t, hash_comm.CommitmentKey{}, k)
	})

	t.Run("valid prng produces full-length key", func(t *testing.T) {
		t.Parallel()
		k, err := hash_comm.SampleCommitmentKey(pcg.NewRandomised())
		require.NoError(t, err)
		require.Len(t, k[:], hash_comm.KeySize)
	})

	t.Run("successive samples differ", func(t *testing.T) {
		t.Parallel()
		prng := pcg.NewRandomised()
		k1, err := hash_comm.SampleCommitmentKey(prng)
		require.NoError(t, err)
		k2, err := hash_comm.SampleCommitmentKey(prng)
		require.NoError(t, err)
		require.NotEqual(t, k1, k2)
	})

	t.Run("sampled key is usable for commit/open roundtrip", func(t *testing.T) {
		t.Parallel()
		prng := pcg.NewRandomised()
		k, err := hash_comm.SampleCommitmentKey(prng)
		require.NoError(t, err)

		w, err := k.SampleWitness(prng)
		require.NoError(t, err)

		msg := hash_comm.Message("hello")
		c, err := k.CommitWithWitness(msg, w)
		require.NoError(t, err)

		require.NoError(t, k.Open(c, msg, w))
	})
}

func TestExtractCommitmentKey(t *testing.T) {
	t.Parallel()

	t.Run("nil transcript", func(t *testing.T) {
		t.Parallel()
		k, err := hash_comm.ExtractCommitmentKey(nil, "label")
		require.Error(t, err)
		require.Contains(t, err.Error(), "nil")
		require.Equal(t, hash_comm.CommitmentKey{}, k)
	})

	t.Run("empty label", func(t *testing.T) {
		t.Parallel()
		k, err := hash_comm.ExtractCommitmentKey(hagrid.NewTranscript("test"), "")
		require.Error(t, err)
		require.Equal(t, hash_comm.CommitmentKey{}, k)
	})

	t.Run("valid transcript and label produces full-length key", func(t *testing.T) {
		t.Parallel()
		k, err := hash_comm.ExtractCommitmentKey(hagrid.NewTranscript("test"), "label")
		require.NoError(t, err)
		require.Len(t, k[:], hash_comm.KeySize)
	})

	t.Run("deterministic on equal transcripts and labels", func(t *testing.T) {
		t.Parallel()
		t1 := hagrid.NewTranscript("test")
		t2 := hagrid.NewTranscript("test")
		t1.AppendBytes("ctx", []byte("payload"))
		t2.AppendBytes("ctx", []byte("payload"))

		k1, err := hash_comm.ExtractCommitmentKey(t1, "label")
		require.NoError(t, err)
		k2, err := hash_comm.ExtractCommitmentKey(t2, "label")
		require.NoError(t, err)
		require.Equal(t, k1, k2)
	})

	t.Run("different labels yield different keys", func(t *testing.T) {
		t.Parallel()
		t1 := hagrid.NewTranscript("test")
		t2 := hagrid.NewTranscript("test")

		k1, err := hash_comm.ExtractCommitmentKey(t1, "label-a")
		require.NoError(t, err)
		k2, err := hash_comm.ExtractCommitmentKey(t2, "label-b")
		require.NoError(t, err)
		require.NotEqual(t, k1, k2)
	})

	t.Run("different transcript names yield different keys", func(t *testing.T) {
		t.Parallel()
		k1, err := hash_comm.ExtractCommitmentKey(hagrid.NewTranscript("name-a"), "label")
		require.NoError(t, err)
		k2, err := hash_comm.ExtractCommitmentKey(hagrid.NewTranscript("name-b"), "label")
		require.NoError(t, err)
		require.NotEqual(t, k1, k2)
	})

	t.Run("different transcript states yield different keys", func(t *testing.T) {
		t.Parallel()
		t1 := hagrid.NewTranscript("test")
		t2 := hagrid.NewTranscript("test")
		t1.AppendBytes("ctx", []byte("payload-a"))
		t2.AppendBytes("ctx", []byte("payload-b"))

		k1, err := hash_comm.ExtractCommitmentKey(t1, "label")
		require.NoError(t, err)
		k2, err := hash_comm.ExtractCommitmentKey(t2, "label")
		require.NoError(t, err)
		require.NotEqual(t, k1, k2)
	})

	t.Run("extracted key is usable for commit/open roundtrip", func(t *testing.T) {
		t.Parallel()
		k, err := hash_comm.ExtractCommitmentKey(hagrid.NewTranscript("test"), "label")
		require.NoError(t, err)

		w, err := k.SampleWitness(pcg.NewRandomised())
		require.NoError(t, err)

		msg := hash_comm.Message("hello")
		c, err := k.CommitWithWitness(msg, w)
		require.NoError(t, err)

		require.NoError(t, k.Open(c, msg, w))
	})
}

func TestCantUnmarshalInvalid(t *testing.T) {
	t.Parallel()

	t.Run("short commitment length", func(t *testing.T) {
		t.Parallel()
		data := bytes.Repeat([]byte{0xAB}, hash_comm.DigestSize-1)
		out, err := serde.UnmarshalCBOR[hash_comm.Commitment](data)
		require.Error(t, err)
		require.Equal(t, hash_comm.Commitment{}, out)
	})

	t.Run("long commitment length", func(t *testing.T) {
		t.Parallel()
		data := bytes.Repeat([]byte{0xAB}, hash_comm.DigestSize+1)
		out, err := serde.UnmarshalCBOR[hash_comm.Commitment](data)
		require.Error(t, err)
		require.Equal(t, hash_comm.Commitment{}, out)
	})

	t.Run("short witness length", func(t *testing.T) {
		t.Parallel()
		data := bytes.Repeat([]byte{0xCD}, hash_comm.DigestSize-1)
		out, err := serde.UnmarshalCBOR[hash_comm.Witness](data)
		require.Error(t, err)
		require.Equal(t, hash_comm.Witness{}, out)
	})

	t.Run("long witness length", func(t *testing.T) {
		t.Parallel()
		data := bytes.Repeat([]byte{0xCD}, hash_comm.DigestSize+1)
		out, err := serde.UnmarshalCBOR[hash_comm.Witness](data)
		require.Error(t, err)
		require.Equal(t, hash_comm.Witness{}, out)
	})

	t.Run("short key length", func(t *testing.T) {
		t.Parallel()
		data := bytes.Repeat([]byte{0xEF}, hash_comm.KeySize-1)
		out, err := serde.UnmarshalCBOR[hash_comm.CommitmentKey](data)
		require.Error(t, err)
		require.Equal(t, hash_comm.CommitmentKey{}, out)
	})

	t.Run("long key length", func(t *testing.T) {
		t.Parallel()
		data := bytes.Repeat([]byte{0xEF}, hash_comm.KeySize+1)
		out, err := serde.UnmarshalCBOR[hash_comm.CommitmentKey](data)
		require.Error(t, err)
		require.Equal(t, hash_comm.CommitmentKey{}, out)
	})
}
