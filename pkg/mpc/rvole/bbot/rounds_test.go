package rvole_bbot_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	rvole_bbot "github.com/bronlabs/bron-crypto/pkg/mpc/rvole/bbot"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	const L = 8
	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	suite, err := rvole_bbot.NewSuite(L, curve)
	require.NoError(t, err)

	const aliceId = 1
	const bobId = 2
	quorum := hashset.NewComparable[sharing.ID](aliceId, bobId).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	alice, err := rvole_bbot.NewAlice(ctxs[aliceId], suite, prng)
	require.NoError(t, err)

	bob, err := rvole_bbot.NewBob(ctxs[bobId], suite, prng)
	require.NoError(t, err)

	r1, err := alice.Round1()
	require.NoError(t, err)

	r2, b, err := bob.Round2(r1)
	require.NoError(t, err)

	a := make([]*k256.Scalar, L)
	for i := range a {
		a[i], err = k256.NewScalarField().Random(prng)
		require.NoError(t, err)
	}
	r3, c, err := alice.Round3(r2, a)
	require.NoError(t, err)

	d, err := bob.Round4(r3)
	require.NoError(t, err)

	t.Run("a_i * b = c_i + d_i", func(t *testing.T) {
		t.Parallel()

		for i := range L {
			product := a[i].Mul(b)
			sum := c[i].Add(d[i])
			require.True(t, product.Equal(sum))
		}
	})

	t.Run("transcripts at the same state", func(t *testing.T) {
		t.Parallel()
		aliceBytes, err := ctxs[aliceId].Transcript().ExtractBytes("test", 32)
		require.NoError(t, err)
		bobBytes, err := ctxs[bobId].Transcript().ExtractBytes("test", 32)
		require.NoError(t, err)
		require.True(t, bytes.Equal(aliceBytes, bobBytes))
	})
}

func setupRound3Message(t *testing.T) (*rvole_bbot.Bob[*k256.Point, *k256.Scalar], *rvole_bbot.Round3P2P[*k256.Point, *k256.Scalar]) {
	t.Helper()
	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	suite, err := rvole_bbot.NewSuite(8, curve)
	require.NoError(t, err)

	const aliceID = 1
	const bobID = 2
	quorum := hashset.NewComparable[sharing.ID](aliceID, bobID).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)
	alice, err := rvole_bbot.NewAlice(ctxs[aliceID], suite, prng)
	require.NoError(t, err)
	bob, err := rvole_bbot.NewBob(ctxs[2], suite, prng)
	require.NoError(t, err)

	r1, err := alice.Round1()
	require.NoError(t, err)
	r2, _, err := bob.Round2(r1)
	require.NoError(t, err)
	a := make([]*k256.Scalar, 8)
	for i := range a {
		a[i], err = k256.NewScalarField().Random(prng)
		require.NoError(t, err)
	}
	r3, _, err := alice.Round3(r2, a)
	require.NoError(t, err)

	return bob, r3
}

func TestRound4RejectsNilATildeEntry(t *testing.T) {
	t.Parallel()

	bob, msg := setupRound3Message(t)
	msg.ATilde[0][0] = nil

	_, err := bob.Round4(msg)
	require.Error(t, err)
}

func TestRound4RejectsNilEtaEntry(t *testing.T) {
	t.Parallel()

	bob, msg := setupRound3Message(t)
	msg.Eta[0] = nil

	_, err := bob.Round4(msg)
	require.Error(t, err)
}
