package hash_comm_test

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
)

func Test_ValidCommitment(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	ck := randomCk(t, prng)
	m := randomMessage(t, prng)

	c, r, err := ck.Commit(m, prng)
	require.NoError(t, err)

	err = ck.Verify(c, m, r)
	require.NoError(t, err)
}

func Test_InvalidCommitment(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	ck := randomCk(t, prng)
	m := randomMessage(t, prng)
	invalidCk := randomCk(t, prng)
	invalidM := randomMessage(t, prng)

	c, r, err := ck.Commit(m, prng)
	require.NoError(t, err)

	err = ck.Verify(c, m, r)
	require.NoError(t, err)

	invalidC, invalidR, err := invalidCk.Commit(invalidM, prng)
	require.NoError(t, err)

	err = invalidCk.Verify(c, m, r)
	require.Error(t, err)
	err = ck.Verify(invalidC, m, r)
	require.Error(t, err)
	err = ck.Verify(c, invalidM, r)
	require.Error(t, err)
	err = ck.Verify(c, m, invalidR)
	require.Error(t, err)
	err = ck.Verify(c, invalidM, invalidR)
	require.Error(t, err)
}

func randomCk(tb testing.TB, prng io.Reader) *hash_comm.CommittingKey {
	tb.Helper()

	var key [32]byte
	_, err := io.ReadFull(prng, key[:])
	require.NoError(tb, err)

	return hash_comm.NewCommittingKey(key)
}

func randomMessage(tb testing.TB, prng io.Reader) hash_comm.Message {
	tb.Helper()

	var message [64]byte
	_, err := io.ReadFull(prng, message[:])
	require.NoError(tb, err)

	return message[:]
}
