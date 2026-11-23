package mrr21_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/mrr21"
)

const (
	senderID   sharing.ID = 1
	receiverID sharing.ID = 2
)

func twoPartyContexts(tb testing.TB, prng io.Reader) map[sharing.ID]*session.Context {
	tb.Helper()
	quorum := hashset.NewComparable[sharing.ID](senderID, receiverID).Freeze()
	return session_testutils.MakeRandomContexts(tb, quorum, prng)
}

func TestHappyPath(t *testing.T) {
	t.Parallel()

	t.Run("k256, 128-bit messages", func(t *testing.T) {
		t.Parallel()
		testHappyPath[ot.Message128](t, k256.NewCurve(), 256)
	})
	t.Run("p256, 256-bit messages", func(t *testing.T) {
		t.Parallel()
		testHappyPath[ot.Message256](t, p256.NewCurve(), 128)
	})
	t.Run("edwards25519 prime subgroup, 128-bit messages", func(t *testing.T) {
		t.Parallel()
		testHappyPath[ot.Message128](t, edwards25519.NewPrimeSubGroup(), 128)
	})
}

func testHappyPath[M ot.Message, G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](tb testing.TB, group algebra.PrimeGroup[G, S], l int) {
	tb.Helper()
	prng := pcg.NewRandomised()
	ctxs := twoPartyContexts(tb, prng)
	sender, err := mrr21.NewSender[M](ctxs[senderID], group, l, prng)
	require.NoError(tb, err)
	receiver, err := mrr21.NewReceiver[M](ctxs[receiverID], group, l, prng)
	require.NoError(tb, err)

	choices := make(ot.Choices, l/8)
	_, err = io.ReadFull(prng, choices)
	require.NoError(tb, err)

	// Round 1, both sides at once: the messages do not depend on each other.
	senderMsg, err := sender.Round1()
	require.NoError(tb, err)
	receiverMsg, err := receiver.Round1(choices)
	require.NoError(tb, err)

	// Round 2, each side on the other's decoded message.
	senderOut, err := sender.Round2(ntu.CBORRoundTrip(tb, receiverMsg))
	require.NoError(tb, err)
	receiverOut, err := receiver.Round2(ntu.CBORRoundTrip(tb, senderMsg))
	require.NoError(tb, err)

	require.Equal(tb, l, senderOut.InferredL())
	require.Equal(tb, l, receiverOut.InferredL())
	require.Equal(tb, choices, receiverOut.Choices())

	pairs := senderOut.Messages()
	chosen := receiverOut.Messages()
	for i := range l {
		ci := (choices[i/8] >> (i % 8)) & 0b1
		require.Equal(tb, pairs[i][ci], chosen[i], "OT %d: receiver must hold the chosen message", i)
		require.NotEqual(tb, pairs[i][1-ci], chosen[i], "OT %d: receiver must not hold the other message", i)
		require.NotEqual(tb, pairs[i][0], pairs[i][1], "OT %d: the two messages must differ", i)
		if i > 0 {
			require.NotEqual(tb, pairs[i-1][0], pairs[i][0], "messages must differ across OTs")
		}
	}

	// Both parties must end with the same transcript: the same bytes extracted
	// under a fresh label on either side.
	senderTape, err := ctxs[senderID].Transcript().ExtractBytes("after-protocol", 32)
	require.NoError(tb, err)
	receiverTape, err := ctxs[receiverID].Transcript().ExtractBytes("after-protocol", 32)
	require.NoError(tb, err)
	require.Equal(tb, senderTape, receiverTape, "transcripts must stay consistent between the parties")
}

type (
	k256Sender          = mrr21.Sender[ot.Message128, *k256.Point, *k256.Scalar]
	k256Receiver        = mrr21.Receiver[ot.Message128, *k256.Point, *k256.Scalar]
	k256SenderRound1    = mrr21.SenderRound1P2P[ot.Message128, *k256.Point, *k256.Scalar]
	k256ReceiverRound1  = mrr21.ReceiverRound1P2P[ot.Message128, *k256.Point, *k256.Scalar]
	k256MasnyRindalPopf = mrr21.MasnyRindalPopf[*k256.Point, *k256.Scalar]
)

func TestMRR21_RoundOrderAndValidation(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	const l = 16

	newPair := func(tb testing.TB) (*k256Sender, *k256Receiver, io.Reader) {
		tb.Helper()
		prng := pcg.NewRandomised()
		ctxs := twoPartyContexts(tb, prng)
		sender, err := mrr21.NewSender[ot.Message128](ctxs[senderID], curve, l, prng)
		require.NoError(tb, err)
		receiver, err := mrr21.NewReceiver[ot.Message128](ctxs[receiverID], curve, l, prng)
		require.NoError(tb, err)
		return sender, receiver, prng
	}

	t.Run("rounds out of order", func(t *testing.T) {
		t.Parallel()
		sender, receiver, _ := newPair(t)
		_, err := sender.Round2(&k256ReceiverRound1{Phis: nil})
		require.ErrorIs(t, err, ot.ErrRound)
		_, err = receiver.Round2(&k256SenderRound1{Ms: nil})
		require.ErrorIs(t, err, ot.ErrRound)

		_, err = sender.Round1()
		require.NoError(t, err)
		_, err = sender.Round1()
		require.ErrorIs(t, err, ot.ErrRound)

		_, err = receiver.Round1(make([]byte, l/8))
		require.NoError(t, err)
		_, err = receiver.Round1(make([]byte, l/8))
		require.ErrorIs(t, err, ot.ErrRound)
	})

	t.Run("receiver rejects choices of the wrong length", func(t *testing.T) {
		t.Parallel()
		_, receiver, _ := newPair(t)
		_, err := receiver.Round1(make([]byte, l/8+1))
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
	})

	t.Run("nil round 1 messages", func(t *testing.T) {
		t.Parallel()
		sender, receiver, _ := newPair(t)
		_, err := sender.Round1()
		require.NoError(t, err)
		_, err = receiver.Round1(make([]byte, l/8))
		require.NoError(t, err)
		_, err = sender.Round2(nil)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
		_, err = receiver.Round2(nil)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
	})

	t.Run("sender rejects a malformed receiver message", func(t *testing.T) {
		t.Parallel()
		sender, receiver, _ := newPair(t)
		_, err := sender.Round1()
		require.NoError(t, err)
		receiverMsg, err := receiver.Round1(make([]byte, l/8))
		require.NoError(t, err)

		tooFew := &k256ReceiverRound1{Phis: receiverMsg.Phis[:l-1]}
		_, err = sender.Round2(tooFew)
		require.ErrorIs(t, err, ot.ErrValidation)

		withNil := &k256ReceiverRound1{Phis: append(receiverMsg.Phis[:l-1:l-1], nil)}
		_, err = sender.Round2(withNil)
		require.ErrorIs(t, err, ot.ErrValidation)

		var zeroPopf k256MasnyRindalPopf
		withZero := &k256ReceiverRound1{Phis: append(receiverMsg.Phis[:l-1:l-1], &zeroPopf)}
		_, err = sender.Round2(withZero)
		require.ErrorIs(t, err, ot.ErrValidation)
	})

	t.Run("receiver rejects a malformed sender message", func(t *testing.T) {
		t.Parallel()
		sender, receiver, _ := newPair(t)
		_, err := sender.Round1()
		require.NoError(t, err)
		_, err = receiver.Round1(make([]byte, l/8))
		require.NoError(t, err)

		_, err = receiver.Round2(&k256SenderRound1{Ms: nil})
		require.ErrorIs(t, err, ot.ErrValidation)
		_, err = receiver.Round2(&k256SenderRound1{Ms: curve.OpIdentity()})
		require.ErrorIs(t, err, ot.ErrValidation)
	})

	t.Run("messages validate their origin", func(t *testing.T) {
		t.Parallel()
		sender, receiver, _ := newPair(t)
		senderMsg, err := sender.Round1()
		require.NoError(t, err)
		receiverMsg, err := receiver.Round1(make([]byte, l/8))
		require.NoError(t, err)
		require.NoError(t, senderMsg.Validate(receiver, senderID))
		require.ErrorIs(t, senderMsg.Validate(receiver, receiverID), ot.ErrValidation)
		require.NoError(t, receiverMsg.Validate(sender, receiverID))
		require.ErrorIs(t, receiverMsg.Validate(sender, senderID), ot.ErrValidation)
	})
}
