package hashcom_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
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

func TestSampleCommitmentKey(t *testing.T) {
	t.Parallel()

	t.Run("nil prng", func(t *testing.T) {
		t.Parallel()
		k, err := hashcom.SampleCommitmentKey(nil)
		require.Error(t, err)
		require.ErrorIs(t, err, commitments.ErrIsNil)
		require.Nil(t, k)
	})

	t.Run("failing reader", func(t *testing.T) {
		t.Parallel()
		k, err := hashcom.SampleCommitmentKey(badReader{})
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("short reader", func(t *testing.T) {
		t.Parallel()
		k, err := hashcom.SampleCommitmentKey(&shortReader{remaining: hashcom.KeySize - 1})
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("valid prng produces full-length key", func(t *testing.T) {
		t.Parallel()
		k, err := hashcom.SampleCommitmentKey(pcg.NewRandomised())
		require.NoError(t, err)
		require.Len(t, k[:], hashcom.KeySize)
	})

	t.Run("successive samples differ", func(t *testing.T) {
		t.Parallel()
		prng := pcg.NewRandomised()
		k1, err := hashcom.SampleCommitmentKey(prng)
		require.NoError(t, err)
		k2, err := hashcom.SampleCommitmentKey(prng)
		require.NoError(t, err)
		require.NotEqual(t, k1, k2)
	})

	t.Run("sampled key is usable for commit/open roundtrip", func(t *testing.T) {
		t.Parallel()
		prng := pcg.NewRandomised()
		k, err := hashcom.SampleCommitmentKey(prng)
		require.NoError(t, err)

		w, err := k.SampleWitness(prng)
		require.NoError(t, err)

		msg := hashcom.Message("hello")
		c, err := k.CommitWithWitness(msg, w)
		require.NoError(t, err)

		require.NoError(t, k.Open(c, msg, w))
	})
}

func TestExtractCommitmentKey(t *testing.T) {
	t.Parallel()

	t.Run("nil transcript", func(t *testing.T) {
		t.Parallel()
		k, err := hashcom.ExtractCommitmentKey(nil, "label")
		require.Error(t, err)
		require.ErrorIs(t, err, commitments.ErrIsNil)
		require.Nil(t, k)
	})

	t.Run("empty label", func(t *testing.T) {
		t.Parallel()
		k, err := hashcom.ExtractCommitmentKey(hagrid.NewTranscript("test"), "")
		require.Error(t, err)
		require.ErrorIs(t, err, commitments.ErrIsNil)
		require.Nil(t, k)
	})

	t.Run("valid transcript and label produces full-length key", func(t *testing.T) {
		t.Parallel()
		k, err := hashcom.ExtractCommitmentKey(hagrid.NewTranscript("test"), "label")
		require.NoError(t, err)
		require.Len(t, k[:], hashcom.KeySize)
	})

	t.Run("deterministic on equal transcripts and labels", func(t *testing.T) {
		t.Parallel()
		t1 := hagrid.NewTranscript("test")
		t2 := hagrid.NewTranscript("test")
		t1.AppendBytes("ctx", []byte("payload"))
		t2.AppendBytes("ctx", []byte("payload"))

		k1, err := hashcom.ExtractCommitmentKey(t1, "label")
		require.NoError(t, err)
		k2, err := hashcom.ExtractCommitmentKey(t2, "label")
		require.NoError(t, err)
		require.Equal(t, k1, k2)
	})

	t.Run("different labels yield different keys", func(t *testing.T) {
		t.Parallel()
		t1 := hagrid.NewTranscript("test")
		t2 := hagrid.NewTranscript("test")

		k1, err := hashcom.ExtractCommitmentKey(t1, "label-a")
		require.NoError(t, err)
		k2, err := hashcom.ExtractCommitmentKey(t2, "label-b")
		require.NoError(t, err)
		require.NotEqual(t, k1, k2)
	})

	t.Run("different transcript names yield different keys", func(t *testing.T) {
		t.Parallel()
		k1, err := hashcom.ExtractCommitmentKey(hagrid.NewTranscript("name-a"), "label")
		require.NoError(t, err)
		k2, err := hashcom.ExtractCommitmentKey(hagrid.NewTranscript("name-b"), "label")
		require.NoError(t, err)
		require.NotEqual(t, k1, k2)
	})

	t.Run("different transcript states yield different keys", func(t *testing.T) {
		t.Parallel()
		t1 := hagrid.NewTranscript("test")
		t2 := hagrid.NewTranscript("test")
		t1.AppendBytes("ctx", []byte("payload-a"))
		t2.AppendBytes("ctx", []byte("payload-b"))

		k1, err := hashcom.ExtractCommitmentKey(t1, "label")
		require.NoError(t, err)
		k2, err := hashcom.ExtractCommitmentKey(t2, "label")
		require.NoError(t, err)
		require.NotEqual(t, k1, k2)
	})

	t.Run("extracted key is usable for commit/open roundtrip", func(t *testing.T) {
		t.Parallel()
		k, err := hashcom.ExtractCommitmentKey(hagrid.NewTranscript("test"), "label")
		require.NoError(t, err)

		w, err := k.SampleWitness(pcg.NewRandomised())
		require.NoError(t, err)

		msg := hashcom.Message("hello")
		c, err := k.CommitWithWitness(msg, w)
		require.NoError(t, err)

		require.NoError(t, k.Open(c, msg, w))
	})
}

func TestCantUnmarshalInvalid(t *testing.T) {
	t.Parallel()

	t.Run("short commitment length", func(t *testing.T) {
		t.Parallel()
		data := bytes.Repeat([]byte{0xAB}, hashcom.DigestSize-1)
		out, err := serde.UnmarshalCBOR[hashcom.Commitment](data)
		require.Error(t, err)
		require.Equal(t, hashcom.Commitment{}, out)
	})

	t.Run("long commitment length", func(t *testing.T) {
		t.Parallel()
		data := bytes.Repeat([]byte{0xAB}, hashcom.DigestSize+1)
		out, err := serde.UnmarshalCBOR[hashcom.Commitment](data)
		require.Error(t, err)
		require.Equal(t, hashcom.Commitment{}, out)
	})

	t.Run("short witness length", func(t *testing.T) {
		t.Parallel()
		data := bytes.Repeat([]byte{0xCD}, hashcom.DigestSize-1)
		out, err := serde.UnmarshalCBOR[hashcom.Witness](data)
		require.Error(t, err)
		require.Equal(t, hashcom.Witness{}, out)
	})

	t.Run("long witness length", func(t *testing.T) {
		t.Parallel()
		data := bytes.Repeat([]byte{0xCD}, hashcom.DigestSize+1)
		out, err := serde.UnmarshalCBOR[hashcom.Witness](data)
		require.Error(t, err)
		require.Equal(t, hashcom.Witness{}, out)
	})

	t.Run("short key length", func(t *testing.T) {
		t.Parallel()
		data := bytes.Repeat([]byte{0xEF}, hashcom.KeySize-1)
		out, err := serde.UnmarshalCBOR[hashcom.CommitmentKey](data)
		require.Error(t, err)
		require.Equal(t, hashcom.CommitmentKey{}, out)
	})

	t.Run("long key length", func(t *testing.T) {
		t.Parallel()
		data := bytes.Repeat([]byte{0xEF}, hashcom.KeySize+1)
		out, err := serde.UnmarshalCBOR[hashcom.CommitmentKey](data)
		require.Error(t, err)
		require.Equal(t, hashcom.CommitmentKey{}, out)
	})
}
