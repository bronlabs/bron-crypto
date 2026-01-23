package hash_comm_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
)

func Test_ValidCommitment(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	ck := randomCk(t, prng)
	m := randomMessage(t, prng)

	committer, err := ck.Committer()
	require.NoError(t, err)
	c, r, err := committer.Commit(m, prng)
	require.NoError(t, err)

	verifier, err := ck.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(c, m, r)
	require.NoError(t, err)
}

func Test_InvalidCommitment(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	scheme := randomCk(t, prng)
	m := randomMessage(t, prng)
	invalidM := randomMessage(t, prng)

	committer, err := scheme.Committer()
	require.NoError(t, err)
	c, r, err := committer.Commit(m, prng)
	require.NoError(t, err)

	invalidC, invalidR, err := committer.Commit(invalidM, prng)
	require.NoError(t, err)

	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(c, m, r)
	require.NoError(t, err)
	err = verifier.Verify(invalidC, m, r)
	require.Error(t, err)
	err = verifier.Verify(c, invalidM, r)
	require.Error(t, err)
	err = verifier.Verify(c, m, invalidR)
	require.Error(t, err)
	err = verifier.Verify(c, invalidM, invalidR)
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
