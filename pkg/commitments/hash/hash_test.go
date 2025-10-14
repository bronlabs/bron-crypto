package hash_comm_test

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/commitments"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
)

func Test_ValidCommitment(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	ck := randomCk(t, prng)
	m := randomMessage(t, prng)

	c, r, err := ck.Committer().Commit(m, prng)
	require.NoError(t, err)

	err = ck.Verifier().Verify(c, m, r)
	require.NoError(t, err)
}

func Test_InvalidCommitment(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	scheme := randomCk(t, prng)
	m := randomMessage(t, prng)
	invalidM := randomMessage(t, prng)

	c, r, err := scheme.Committer().Commit(m, prng)
	require.NoError(t, err)

	invalidC, invalidR, err := scheme.Committer().Commit(invalidM, prng)
	require.NoError(t, err)

	err = scheme.Verifier().Verify(c, m, r)
	require.NoError(t, err)
	err = scheme.Verifier().Verify(invalidC, m, r)
	require.Error(t, err)
	err = scheme.Verifier().Verify(c, invalidM, r)
	require.Error(t, err)
	err = scheme.Verifier().Verify(c, m, invalidR)
	require.Error(t, err)
	err = scheme.Verifier().Verify(c, invalidM, invalidR)
	require.Error(t, err)
}

func randomCk(tb testing.TB, prng io.Reader) commitments.Scheme[hash_comm.Key, hash_comm.Witness, hash_comm.Message, hash_comm.Commitment, *hash_comm.Committer, *hash_comm.Verifier] {
	tb.Helper()

	var key hash_comm.Key
	_, err := io.ReadFull(prng, key[:])
	require.NoError(tb, err)
	scheme, err := hash_comm.NewScheme(key)
	require.NoError(tb, err)

	return scheme
}

func randomMessage(tb testing.TB, prng io.Reader) hash_comm.Message {
	tb.Helper()

	var message [64]byte
	_, err := io.ReadFull(prng, message[:])
	require.NoError(tb, err)

	return message[:]
}
