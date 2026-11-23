package rvole_mrr21_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/rvole"
	rvole_mrr21 "github.com/bronlabs/bron-crypto/pkg/mpc/rvole/mrr21"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

const (
	aliceID = sharing.ID(1)
	bobID   = sharing.ID(2)
)

type (
	suite   = rvole.Suite[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]
	alice   = rvole_mrr21.Alice[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]
	bob     = rvole_mrr21.Bob[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]
	round2  = rvole_mrr21.AliceRound2P2P[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]
	message = rvole.MultiplyMessage[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]
)

func fixture(tb testing.TB, l int) (map[sharing.ID]*session.Context, *suite, *alice, *bob) {
	tb.Helper()
	prng := pcg.NewRandomised()
	s, err := rvole.NewSuite(l, k256.NewCurve())
	require.NoError(tb, err)
	ctxs := session_testutils.MakeRandomContexts(tb, hashset.NewComparable(aliceID, bobID).Freeze(), prng)
	a, err := rvole_mrr21.NewAlice(ctxs[aliceID], s, prng)
	require.NoError(tb, err)
	b, err := rvole_mrr21.NewBob(ctxs[bobID], s, prng)
	require.NoError(tb, err)
	return ctxs, s, a, b
}

func randomInput(tb testing.TB, l int) []*k256.Scalar {
	tb.Helper()
	prng := pcg.NewRandomised()
	a := make([]*k256.Scalar, l)
	for i := range a {
		var err error
		a[i], err = k256.NewScalarField().Random(prng)
		require.NoError(tb, err)
	}
	return a
}

// run drives the three rounds with every message serialised and returns the
// correlation (a, b, c, d).
func run(tb testing.TB, alice *alice, bob *bob, a []*k256.Scalar) (*k256.Scalar, []*k256.Scalar, []*k256.Scalar) {
	tb.Helper()
	aliceR1, err := alice.Round1()
	require.NoError(tb, err)
	bobR1, err := bob.Round1()
	require.NoError(tb, err)
	b, err := bob.Round2(ntu.CBORRoundTrip(tb, aliceR1))
	require.NoError(tb, err)
	aliceR2, c, err := alice.Round2(ntu.CBORRoundTrip(tb, bobR1), a)
	require.NoError(tb, err)
	d, err := bob.Round3(ntu.CBORRoundTrip(tb, aliceR2))
	require.NoError(tb, err)
	return b, c, d
}

func requireCorrelation(tb testing.TB, a []*k256.Scalar, b *k256.Scalar, c, d []*k256.Scalar) {
	tb.Helper()
	require.Len(tb, c, len(a))
	require.Len(tb, d, len(a))
	for i := range a {
		require.True(tb, a[i].Mul(b).Equal(c[i].Add(d[i])), "a_%d * b != c_%d + d_%d", i, i, i)
	}
}

func requireTranscriptsMatch(tb testing.TB, ctxs map[sharing.ID]*session.Context) {
	tb.Helper()
	aliceBytes, err := ctxs[aliceID].Transcript().ExtractBytes("test", 32)
	require.NoError(tb, err)
	bobBytes, err := ctxs[bobID].Transcript().ExtractBytes("test", 32)
	require.NoError(tb, err)
	require.True(tb, bytes.Equal(aliceBytes, bobBytes))
}

func TestHappyPath(t *testing.T) {
	t.Parallel()
	for _, l := range []int{1, 2} {
		t.Run("", func(t *testing.T) {
			t.Parallel()
			ctxs, s, alice, bob := fixture(t, l)
			require.Equal(t, 1792, s.Xi())
			require.Equal(t, 256, ot.MessageBitLen[rvole_mrr21.Message]())
			a := randomInput(t, l)
			b, c, d := run(t, alice, bob, a)
			requireCorrelation(t, a, b, c, d)
			requireTranscriptsMatch(t, ctxs)
		})
	}
}

func TestConsistencyCheckRejectsTampering(t *testing.T) {
	t.Parallel()
	tamper := map[string]func(m *message){
		"mu":     func(m *message) { m.Mu[0] ^= 1 },
		"aTilde": func(m *message) { m.ATilde[3][0] = m.ATilde[3][0].Add(k256.NewScalarField().One()) },
		"eta":    func(m *message) { m.Eta[0] = m.Eta[0].Add(k256.NewScalarField().One()) },
	}
	for name, f := range tamper {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			const l = 2
			_, _, alice, bob := fixture(t, l)
			aliceR1, err := alice.Round1()
			require.NoError(t, err)
			bobR1, err := bob.Round1()
			require.NoError(t, err)
			_, err = bob.Round2(aliceR1)
			require.NoError(t, err)
			aliceR2, _, err := alice.Round2(bobR1, randomInput(t, l))
			require.NoError(t, err)
			f(aliceR2.Multiply)
			_, err = bob.Round3(aliceR2)
			require.ErrorIs(t, err, base.ErrAbort)
			require.Equal(t, []sharing.ID{aliceID}, base.GetMaliciousIdentities[sharing.ID](err))
		})
	}
}

func TestValidation(t *testing.T) {
	t.Parallel()

	t.Run("constructors", func(t *testing.T) {
		t.Parallel()
		prng := pcg.NewRandomised()
		s, err := rvole.NewSuite(2, k256.NewCurve())
		require.NoError(t, err)
		ctxs := session_testutils.MakeRandomContexts(t, hashset.NewComparable(aliceID, bobID).Freeze(), prng)
		_, err = rvole_mrr21.NewAlice(nil, s, prng)
		require.ErrorIs(t, err, rvole.ErrInvalidArgument)
		_, err = rvole_mrr21.NewAlice(ctxs[aliceID], s, nil)
		require.ErrorIs(t, err, rvole.ErrInvalidArgument)
		_, err = rvole_mrr21.NewBob[*k256.Point, *k256.BaseFieldElement, *k256.Scalar](ctxs[bobID], nil, prng)
		require.ErrorIs(t, err, rvole.ErrInvalidArgument)
	})

	t.Run("rounds and messages", func(t *testing.T) {
		t.Parallel()
		const l = 2
		_, _, alice, bob := fixture(t, l)
		_, err := bob.Round2(nil)
		require.ErrorIs(t, err, rvole.ErrRound)
		_, _, err = alice.Round2(nil, nil)
		require.ErrorIs(t, err, rvole.ErrRound)

		aliceR1, err := alice.Round1()
		require.NoError(t, err)
		_, err = alice.Round1()
		require.ErrorIs(t, err, rvole.ErrRound)
		bobR1, err := bob.Round1()
		require.NoError(t, err)
		_, err = bob.Round1()
		require.ErrorIs(t, err, rvole.ErrRound)

		_, err = bob.Round2(nil)
		require.ErrorIs(t, err, rvole.ErrValidation)
		require.ErrorIs(t, aliceR1.Validate(bob, aliceID+1), rvole.ErrValidation)
		require.ErrorIs(t, bobR1.Validate(alice, bobID+1), rvole.ErrValidation)
		_, err = bob.Round2(aliceR1)
		require.NoError(t, err)
		_, err = bob.Round2(aliceR1)
		require.ErrorIs(t, err, rvole.ErrRound)

		a := randomInput(t, l)
		_, _, err = alice.Round2(bobR1, a[:1])
		require.ErrorIs(t, err, rvole.ErrInvalidArgument)
		aliceR2, _, err := alice.Round2(bobR1, a)
		require.NoError(t, err)
		_, _, err = alice.Round2(bobR1, a)
		require.ErrorIs(t, err, rvole.ErrRound)

		m := aliceR2.Multiply
		require.ErrorIs(t, aliceR2.Validate(bob, aliceID+1), rvole.ErrValidation)
		short := &round2{Multiply: &message{ATilde: m.ATilde[:len(m.ATilde)-1], Eta: m.Eta, Mu: m.Mu}}
		require.ErrorIs(t, short.Validate(bob, aliceID), rvole.ErrValidation)
		require.ErrorIs(t, (&round2{Multiply: nil}).Validate(bob, aliceID), rvole.ErrValidation)
		require.NoError(t, aliceR2.Validate(bob, aliceID))
	})
}
