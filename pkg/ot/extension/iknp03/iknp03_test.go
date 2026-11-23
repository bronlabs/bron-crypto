package iknp03_test

import (
	"crypto/subtle"
	"io"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/mrr21"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/iknp03"
)

const (
	extSenderID   sharing.ID = 1
	extReceiverID sharing.ID = 2
	kappa                    = 128
)

func twoPartyContexts(tb testing.TB, prng io.Reader) map[sharing.ID]*session.Context {
	tb.Helper()
	quorum := hashset.NewComparable[sharing.ID](extSenderID, extReceiverID).Freeze()
	return session_testutils.MakeRandomContexts(tb, quorum, prng)
}

func randomBytes(tb testing.TB, prng io.Reader, n int) []byte {
	tb.Helper()
	out := make([]byte, n)
	_, err := io.ReadFull(prng, out)
	require.NoError(tb, err)
	return out
}

func randomSeed(tb testing.TB, prng io.Reader) iknp03.Seed {
	tb.Helper()
	var seed iknp03.Seed
	_, err := io.ReadFull(prng, ot.MessageAsSlice(&seed))
	require.NoError(tb, err)
	return seed
}

// syntheticBaseOTs fabricates the outputs of k base OTs with the roles reversed:
// the extension sender gets Δ and the seeds it selects, the extension receiver
// both seeds of every base OT.
func syntheticBaseOTs(tb testing.TB, prng io.Reader, k int) (*ot.ReceiverOutput[iknp03.Seed], *ot.SenderOutput[iknp03.Seed]) {
	tb.Helper()
	pairs := make([][2]iknp03.Seed, k)
	chosen := make([]iknp03.Seed, k)
	delta := randomBytes(tb, prng, k/8)
	for i := range k {
		pairs[i] = [2]iknp03.Seed{randomSeed(tb, prng), randomSeed(tb, prng)}
		chosen[i] = pairs[i][(delta[i/8]>>(i%8))&0b1]
	}
	baseReceiverOut, err := ot.NewReceiverOutput(delta, chosen)
	require.NoError(tb, err)
	baseSenderOut, err := ot.NewSenderOutput(pairs)
	require.NoError(tb, err)
	return baseReceiverOut, baseSenderOut
}

func bit(packed []byte, i int) byte { return (packed[i/8] >> (i % 8)) & 0b1 }

// checkCorrelation verifies the F_COTe correlation: the receiver's message j
// equals q_j XOR x_j·Δ.
func checkCorrelation[M ot.Message](tb testing.TB, choices []byte, senderOut *ot.SenderCorrelatedOutput[M], receiverOut *ot.ReceiverOutput[M]) {
	tb.Helper()
	l := len(choices) * 8
	require.Equal(tb, l, senderOut.InferredL())
	require.Equal(tb, l, receiverOut.InferredL())
	delta := senderOut.Delta()
	for j := range l {
		expected := senderOut.Messages()[j]
		if bit(choices, j) == 1 {
			subtle.XORBytes(ot.MessageAsSlice(&expected), ot.MessageAsSlice(&expected), ot.MessageAsSlice(&delta))
		}
		require.Equal(tb, expected, receiverOut.Messages()[j], "OT %d", j)
		require.NotEqual(tb, senderOut.Messages()[j], delta)
	}
}

func TestExtend_SyntheticBaseOTs(t *testing.T) {
	t.Parallel()
	t.Run("128-bit rows", func(t *testing.T) {
		t.Parallel()
		testExtendSynthetic[ot.Message128](t)
	})
	t.Run("256-bit rows", func(t *testing.T) {
		t.Parallel()
		testExtendSynthetic[ot.Message256](t)
	})
}

func testExtendSynthetic[M ot.Message](t *testing.T) {
	t.Helper()
	prng := pcg.NewRandomised()
	ctxs := twoPartyContexts(t, prng)
	baseReceiverOut, baseSenderOut := syntheticBaseOTs(t, prng, ot.MessageBitLen[M]())

	sender, err := iknp03.NewSender[M](ctxs[extSenderID], baseReceiverOut)
	require.NoError(t, err)
	receiver, err := iknp03.NewReceiver[M](ctxs[extReceiverID], baseSenderOut)
	require.NoError(t, err)

	// Two extensions of different sizes from the same PRGs.
	var previous *ot.SenderCorrelatedOutput[M]
	for _, l := range []int{256, 64} {
		choices := randomBytes(t, prng, l/8)
		receiverOut, extend, _, err := receiver.Extend(choices)
		require.NoError(t, err)
		senderOut, _, err := sender.Extend(ntu.CBORRoundTrip(t, extend))
		require.NoError(t, err)
		checkCorrelation(t, choices, senderOut, receiverOut)
		if previous != nil {
			require.NotEqual(t, previous.Messages()[0], senderOut.Messages()[0], "later extensions use fresh keystream")
		}
		previous = senderOut
	}

	senderTape, err := ctxs[extSenderID].Transcript().ExtractBytes("after-extensions", 32)
	require.NoError(t, err)
	receiverTape, err := ctxs[extReceiverID].Transcript().ExtractBytes("after-extensions", 32)
	require.NoError(t, err)
	require.Equal(t, senderTape, receiverTape, "transcripts must stay consistent")
}

func TestExtend_OnMRR21BaseOTs(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	ctxs := twoPartyContexts(t, prng)
	curve := k256.NewCurve()

	// Roles reversed: the extension sender is the base-OT receiver.
	baseReceiver, err := mrr21.NewReceiver[iknp03.Seed](ctxs[extSenderID], curve, kappa, prng)
	require.NoError(t, err)
	baseSender, err := mrr21.NewSender[iknp03.Seed](ctxs[extReceiverID], curve, kappa, prng)
	require.NoError(t, err)
	delta := randomBytes(t, prng, kappa/8)
	baseSenderMsg, err := baseSender.Round1()
	require.NoError(t, err)
	baseReceiverMsg, err := baseReceiver.Round1(delta)
	require.NoError(t, err)
	baseSenderOut, err := baseSender.Round2(ntu.CBORRoundTrip(t, baseReceiverMsg))
	require.NoError(t, err)
	baseReceiverOut, err := baseReceiver.Round2(ntu.CBORRoundTrip(t, baseSenderMsg))
	require.NoError(t, err)

	sender, err := iknp03.NewSender[ot.Message128](ctxs[extSenderID], baseReceiverOut)
	require.NoError(t, err)
	receiver, err := iknp03.NewReceiver[ot.Message128](ctxs[extReceiverID], baseSenderOut)
	require.NoError(t, err)

	choices := randomBytes(t, prng, 1024/8)
	receiverOut, extend, _, err := receiver.Extend(choices)
	require.NoError(t, err)
	senderOut, _, err := sender.Extend(ntu.CBORRoundTrip(t, extend))
	require.NoError(t, err)
	checkCorrelation(t, choices, senderOut, receiverOut)
	gotDelta := senderOut.Delta()
	require.Equal(t, delta, ot.MessageAsSlice(&gotDelta), "Δ is the base-OT choice vector")
}

func TestPRG(t *testing.T) {
	t.Parallel()

	t.Run("rejects bad parameters", func(t *testing.T) {
		t.Parallel()
		seed := randomSeed(t, pcg.NewRandomised())
		_, err := iknp03.NewPRG(seed, -1, 0)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
		_, err = iknp03.NewPRG(seed, 0, 2)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
		var nilPRG *iknp03.PRG
		_, err = nilPRG.Read(make([]byte, 8))
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
	})

	t.Run("deterministic, domain separated, continuous", func(t *testing.T) {
		t.Parallel()
		seed := randomSeed(t, pcg.NewRandomised())
		read := func(i int, j byte, n int) []byte {
			prg, err := iknp03.NewPRG(seed, i, j)
			require.NoError(t, err)
			out := make([]byte, n)
			_, err = prg.Read(out)
			require.NoError(t, err)
			return out
		}
		reference := read(3, 1, 64)
		require.Equal(t, reference, read(3, 1, 64), "same seed, index and branch give the same stream")
		require.NotEqual(t, reference, read(3, 0, 64), "the branch bit separates streams")
		require.NotEqual(t, reference, read(4, 1, 64), "the index separates streams")
		require.NotEqual(t, reference, make([]byte, 64))

		prg, err := iknp03.NewPRG(seed, 3, 1)
		require.NoError(t, err)
		first := make([]byte, 40)
		second := make([]byte, 24)
		_, err = prg.Read(first)
		require.NoError(t, err)
		_, err = prg.Read(second)
		require.NoError(t, err)
		require.Equal(t, reference, slices.Concat(first, second), "successive reads continue the keystream")
	})
}

// fixture builds fresh contexts, PRNG and synthetic base OTs for one subtest;
// contexts cannot be shared, since constructing a participant appends to the
// session transcript.
func fixture(tb testing.TB) (map[sharing.ID]*session.Context, io.Reader, *ot.ReceiverOutput[iknp03.Seed], *ot.SenderOutput[iknp03.Seed]) {
	tb.Helper()
	prng := pcg.NewRandomised()
	ctxs := twoPartyContexts(tb, prng)
	baseReceiverOut, baseSenderOut := syntheticBaseOTs(tb, prng, kappa)
	return ctxs, prng, baseReceiverOut, baseSenderOut
}

func TestValidation(t *testing.T) {
	t.Parallel()

	t.Run("constructors reject bad inputs", func(t *testing.T) {
		t.Parallel()
		ctxs, prng, baseReceiverOut, baseSenderOut := fixture(t)
		_, err := iknp03.NewSender[ot.Message128](nil, baseReceiverOut)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
		_, err = iknp03.NewReceiver[ot.Message128](nil, baseSenderOut)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
		_, err = iknp03.NewSender[ot.Message128](ctxs[extSenderID], nil)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
		_, err = iknp03.NewReceiver[ot.Message128](ctxs[extReceiverID], nil)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)

		threeParties := hashset.NewComparable[sharing.ID](1, 2, 3).Freeze()
		ctx3 := session_testutils.MakeRandomContexts(t, threeParties, prng)[1]
		_, err = iknp03.NewSender[ot.Message128](ctx3, baseReceiverOut)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)

		// 128 base OTs cannot produce 256-bit rows, and 120 cannot produce any.
		_, err = iknp03.NewSender[ot.Message256](ctxs[extSenderID], baseReceiverOut)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
		_, err = iknp03.NewReceiver[ot.Message256](ctxs[extReceiverID], baseSenderOut)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
		shortReceiverOut, shortSenderOut := syntheticBaseOTs(t, prng, 120)
		_, err = iknp03.NewSender[ot.Message128](ctxs[extSenderID], shortReceiverOut)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
		_, err = iknp03.NewReceiver[ot.Message128](ctxs[extReceiverID], shortSenderOut)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
	})

	t.Run("receiver rejects bad choice lengths", func(t *testing.T) {
		t.Parallel()
		ctxs, _, _, baseSenderOut := fixture(t)
		receiver, err := iknp03.NewReceiver[ot.Message128](ctxs[extReceiverID], baseSenderOut)
		require.NoError(t, err)
		_, _, _, err = receiver.Extend(nil)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
		_, _, _, err = receiver.Extend(make([]byte, 9))
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
		_, _, _, err = receiver.Extend(make([]byte, iknp03.MaxExtension/8+8))
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
	})

	t.Run("sender rejects oversized extensions", func(t *testing.T) {
		t.Parallel()
		ctxs, _, baseReceiverOut, _ := fixture(t)
		sender, err := iknp03.NewSender[ot.Message128](ctxs[extSenderID], baseReceiverOut)
		require.NoError(t, err)
		oversized := &iknp03.RoundExtendP2P[ot.Message128]{U: make([][]byte, kappa)}
		for i := range oversized.U {
			oversized.U[i] = make([]byte, iknp03.MaxExtension/8+8)
		}
		_, _, err = sender.Extend(oversized)
		require.ErrorIs(t, err, ot.ErrValidation)
	})

	t.Run("sender rejects malformed messages", func(t *testing.T) {
		t.Parallel()
		ctxs, _, baseReceiverOut, baseSenderOut := fixture(t)
		sender, err := iknp03.NewSender[ot.Message128](ctxs[extSenderID], baseReceiverOut)
		require.NoError(t, err)
		receiver, err := iknp03.NewReceiver[ot.Message128](ctxs[extReceiverID], baseSenderOut)
		require.NoError(t, err)
		_, extend, _, err := receiver.Extend(make([]byte, 8))
		require.NoError(t, err)

		_, _, err = sender.Extend(nil)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
		_, _, err = sender.Extend(&iknp03.RoundExtendP2P[ot.Message128]{U: extend.U[:kappa-1]})
		require.ErrorIs(t, err, ot.ErrValidation)
		ragged := &iknp03.RoundExtendP2P[ot.Message128]{U: append(extend.U[:kappa-1:kappa-1], extend.U[kappa-1][:7])}
		_, _, err = sender.Extend(ragged)
		require.ErrorIs(t, err, ot.ErrValidation)
		empty := make([][]byte, kappa)
		for i := range empty {
			empty[i] = []byte{}
		}
		_, _, err = sender.Extend(&iknp03.RoundExtendP2P[ot.Message128]{U: empty})
		require.ErrorIs(t, err, ot.ErrValidation)
		require.ErrorIs(t, extend.Validate(sender, extSenderID), ot.ErrValidation)
		require.NoError(t, extend.Validate(sender, extReceiverID))
	})
}

// TestOneRoundTripFlow runs base OTs and one extension in a single round trip.
// The extension sender A plays the base-OT receiver and speaks first (φ_1..φ_κ);
// B, the base-OT sender and extension receiver, needs nothing from A to form
// m_S, and after φ arrives it holds both seeds of every base OT, so it can
// answer with m_S and the extension message U in one reply; A then derives its
// seeds from m_S and finishes the extension.
func TestOneRoundTripFlow(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	ctxs := twoPartyContexts(t, prng)
	curve := k256.NewCurve()
	const l = 512

	// A, message 1: base-OT receiver round 1.
	delta := randomBytes(t, prng, kappa/8)
	baseReceiver, err := mrr21.NewReceiver[iknp03.Seed](ctxs[extSenderID], curve, kappa, prng)
	require.NoError(t, err)
	phis, err := baseReceiver.Round1(delta)
	require.NoError(t, err)

	// B, message 2: base-OT sender rounds 1 and 2, then the extension.
	baseSender, err := mrr21.NewSender[iknp03.Seed](ctxs[extReceiverID], curve, kappa, prng)
	require.NoError(t, err)
	ms, err := baseSender.Round1()
	require.NoError(t, err)
	baseSenderOut, err := baseSender.Round2(ntu.CBORRoundTrip(t, phis))
	require.NoError(t, err)
	extReceiver, err := iknp03.NewReceiver[ot.Message128](ctxs[extReceiverID], baseSenderOut)
	require.NoError(t, err)
	choices := randomBytes(t, prng, l/8)
	receiverOut, extend, _, err := extReceiver.Extend(choices)
	require.NoError(t, err)

	// A, on the reply: base-OT receiver round 2, then the extension.
	baseReceiverOut, err := baseReceiver.Round2(ntu.CBORRoundTrip(t, ms))
	require.NoError(t, err)
	extSender, err := iknp03.NewSender[ot.Message128](ctxs[extSenderID], baseReceiverOut)
	require.NoError(t, err)
	senderOut, _, err := extSender.Extend(ntu.CBORRoundTrip(t, extend))
	require.NoError(t, err)

	checkCorrelation(t, choices, senderOut, receiverOut)
	gotDelta := senderOut.Delta()
	require.Equal(t, delta, ot.MessageAsSlice(&gotDelta))

	senderTape, err := ctxs[extSenderID].Transcript().ExtractBytes("after-flow", 32)
	require.NoError(t, err)
	receiverTape, err := ctxs[extReceiverID].Transcript().ExtractBytes("after-flow", 32)
	require.NoError(t, err)
	require.Equal(t, senderTape, receiverTape, "transcripts must match after the one-round-trip flow")
}
