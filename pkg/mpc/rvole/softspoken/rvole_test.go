package rvole_softspoken_test

import (
	"bytes"
	"io"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/rvole"
	rvole_softspoken "github.com/bronlabs/bron-crypto/pkg/mpc/rvole/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/mrr21"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/iknp03"
)

const (
	aliceID = sharing.ID(1)
	bobID   = sharing.ID(2)
	kappa   = 128
)

type (
	suite   = rvole.Suite[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]
	alice   = rvole_softspoken.Alice[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]
	bob     = rvole_softspoken.Bob[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]
	round2  = rvole_softspoken.Round2P2P[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]
	message = rvole.MultiplyMessage[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]
)

func randomBlock(tb testing.TB, prng io.Reader) []byte {
	tb.Helper()
	out := make([]byte, 16)
	_, err := io.ReadFull(prng, out)
	require.NoError(tb, err)
	return out
}

func randomSeed(tb testing.TB, prng io.Reader) iknp03.Seed {
	tb.Helper()
	var seed iknp03.Seed
	_, err := io.ReadFull(prng, seed[:])
	require.NoError(tb, err)
	return seed
}

// syntheticBaseOTs fabricates κ base OTs: Alice's receiver output and Bob's
// sender output.
func syntheticBaseOTs(tb testing.TB, prng io.Reader) (*ot.ReceiverOutput[iknp03.Seed], *ot.SenderOutput[iknp03.Seed]) {
	tb.Helper()
	pairs := make([][2]iknp03.Seed, kappa)
	chosen := make([]iknp03.Seed, kappa)
	choices := randomBlock(tb, prng)
	for i := range kappa {
		pairs[i] = [2]iknp03.Seed{randomSeed(tb, prng), randomSeed(tb, prng)}
		chosen[i] = pairs[i][(choices[i/8]>>(i%8))&0b1]
	}
	receiverOut, err := ot.NewReceiverOutput(choices, chosen)
	require.NoError(tb, err)
	senderOut, err := ot.NewSenderOutput(pairs)
	require.NoError(tb, err)
	return receiverOut, senderOut
}

func fixture(tb testing.TB, l int) (map[sharing.ID]*session.Context, *suite, *alice, *bob) {
	tb.Helper()
	prng := pcg.NewRandomised()
	s, err := rvole.NewSuite(l, k256.NewCurve())
	require.NoError(tb, err)
	ctxs := session_testutils.MakeRandomContexts(tb, hashset.NewComparable(aliceID, bobID).Freeze(), prng)
	aliceBase, bobBase := syntheticBaseOTs(tb, prng)
	a, err := rvole_softspoken.NewAlice(ctxs[aliceID], s, aliceBase, prng)
	require.NoError(tb, err)
	b, err := rvole_softspoken.NewBob(ctxs[bobID], s, bobBase, prng)
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
	for _, l := range []int{1, 2, 16} {
		t.Run("", func(t *testing.T) {
			t.Parallel()
			ctxs, s, alice, bob := fixture(t, l)
			require.Equal(t, 1792, s.Xi())

			r1, b, err := bob.Round1()
			require.NoError(t, err)
			a := randomInput(t, l)
			r2, c, err := alice.Round2(ntu.CBORRoundTrip(t, r1), a)
			require.NoError(t, err)
			d, err := bob.Round3(ntu.CBORRoundTrip(t, r2))
			require.NoError(t, err)

			requireCorrelation(t, a, b, c, d)
			requireTranscriptsMatch(t, ctxs)
		})
	}
}

// TestOnMRR21BaseOTs runs the base OTs with MRR21 in one round trip on the
// same pairwise session, so the gadget and θ bind the base-OT transcript.
func TestOnMRR21BaseOTs(t *testing.T) {
	t.Parallel()
	const l = 2
	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	s, err := rvole.NewSuite(l, curve)
	require.NoError(t, err)
	ctxs := session_testutils.MakeRandomContexts(t, hashset.NewComparable(aliceID, bobID).Freeze(), prng)

	// Alice is the base-OT receiver, Bob the base-OT sender.
	baseReceiver, err := mrr21.NewReceiver[iknp03.Seed](ctxs[aliceID], curve, kappa, prng)
	require.NoError(t, err)
	baseSender, err := mrr21.NewSender[iknp03.Seed](ctxs[bobID], curve, kappa, prng)
	require.NoError(t, err)
	senderR1, err := baseSender.Round1()
	require.NoError(t, err)
	receiverR1, err := baseReceiver.Round1(randomBlock(t, prng))
	require.NoError(t, err)
	aliceBase, err := baseReceiver.Round2(ntu.CBORRoundTrip(t, senderR1))
	require.NoError(t, err)
	bobBase, err := baseSender.Round2(ntu.CBORRoundTrip(t, receiverR1))
	require.NoError(t, err)

	alice, err := rvole_softspoken.NewAlice(ctxs[aliceID], s, aliceBase, prng)
	require.NoError(t, err)
	bob, err := rvole_softspoken.NewBob(ctxs[bobID], s, bobBase, prng)
	require.NoError(t, err)

	r1, b, err := bob.Round1()
	require.NoError(t, err)
	a := randomInput(t, l)
	r2, c, err := alice.Round2(ntu.CBORRoundTrip(t, r1), a)
	require.NoError(t, err)
	d, err := bob.Round3(ntu.CBORRoundTrip(t, r2))
	require.NoError(t, err)

	requireCorrelation(t, a, b, c, d)
	requireTranscriptsMatch(t, ctxs)
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
			r1, _, err := bob.Round1()
			require.NoError(t, err)
			r2, _, err := alice.Round2(r1, randomInput(t, l))
			require.NoError(t, err)
			f(r2.Multiply)
			_, err = bob.Round3(r2)
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
		_, err := rvole.NewSuite(0, k256.NewCurve())
		require.ErrorIs(t, err, rvole.ErrInvalidArgument)
		s, err := rvole.NewSuite(2, k256.NewCurve())
		require.NoError(t, err)
		ctxs := session_testutils.MakeRandomContexts(t, hashset.NewComparable(aliceID, bobID).Freeze(), prng)
		aliceBase, bobBase := syntheticBaseOTs(t, prng)
		_, err = rvole_softspoken.NewAlice(nil, s, aliceBase, prng)
		require.ErrorIs(t, err, rvole.ErrInvalidArgument)
		_, err = rvole_softspoken.NewAlice(ctxs[aliceID], s, nil, prng)
		require.Error(t, err)
		_, err = rvole_softspoken.NewBob[*k256.Point, *k256.BaseFieldElement, *k256.Scalar](ctxs[bobID], nil, bobBase, prng)
		require.ErrorIs(t, err, rvole.ErrInvalidArgument)
		_, err = rvole_softspoken.NewBob(ctxs[bobID], s, bobBase, nil)
		require.ErrorIs(t, err, rvole.ErrInvalidArgument)
	})

	t.Run("rounds and messages", func(t *testing.T) {
		t.Parallel()
		const l = 2
		_, _, alice, bob := fixture(t, l)
		_, err := bob.Round3(nil)
		require.ErrorIs(t, err, rvole.ErrRound)
		r1, _, err := bob.Round1()
		require.NoError(t, err)
		_, _, err = bob.Round1()
		require.ErrorIs(t, err, rvole.ErrRound)

		a := randomInput(t, l)
		_, _, err = alice.Round2(r1, a[:1])
		require.ErrorIs(t, err, rvole.ErrInvalidArgument)
		bad := slices.Clone(a)
		bad[0] = nil
		_, _, err = alice.Round2(r1, bad)
		require.ErrorIs(t, err, rvole.ErrInvalidArgument)
		_, _, err = alice.Round2(nil, a)
		require.ErrorIs(t, err, rvole.ErrValidation)
		require.ErrorIs(t, r1.Validate(alice, bobID+1), rvole.ErrValidation)
		require.NoError(t, r1.Validate(alice, bobID))

		r2, _, err := alice.Round2(r1, a)
		require.NoError(t, err)
		_, _, err = alice.Round2(r1, a)
		require.ErrorIs(t, err, rvole.ErrRound)

		m := r2.Multiply
		require.ErrorIs(t, r2.Validate(bob, aliceID+1), rvole.ErrValidation)
		short := &round2{Multiply: &message{ATilde: m.ATilde[:len(m.ATilde)-1], Eta: m.Eta, Mu: m.Mu}}
		require.ErrorIs(t, short.Validate(bob, aliceID), rvole.ErrValidation)
		narrow := &round2{Multiply: &message{ATilde: append([][]*k256.Scalar{m.ATilde[0][:l]}, m.ATilde[1:]...), Eta: m.Eta, Mu: m.Mu}}
		require.ErrorIs(t, narrow.Validate(bob, aliceID), rvole.ErrValidation)
		noEta := &round2{Multiply: &message{ATilde: m.ATilde, Eta: nil, Mu: m.Mu}}
		require.ErrorIs(t, noEta.Validate(bob, aliceID), rvole.ErrValidation)
		shortMu := &round2{Multiply: &message{ATilde: m.ATilde, Eta: m.Eta, Mu: m.Mu[:31]}}
		require.ErrorIs(t, shortMu.Validate(bob, aliceID), rvole.ErrValidation)
		require.ErrorIs(t, (&round2{Multiply: nil}).Validate(bob, aliceID), rvole.ErrValidation)
		require.NoError(t, r2.Validate(bob, aliceID))
	})
}
