package softspoken_test

import (
	"io"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/binaryfields/bf128"
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
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
)

const (
	extSenderID   sharing.ID = 1
	extReceiverID sharing.ID = 2
	kappa                    = 128
)

type message = softspoken.RoundExtendP2P

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

// syntheticBaseOTs fabricates the outputs of k base OTs with the roles
// reversed, as in the IKNP03 tests.
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

// fixture builds fresh contexts, PRNG, base OTs and participants for one test.
func fixture(tb testing.TB) (map[sharing.ID]*session.Context, *softspoken.Sender, *softspoken.Receiver) {
	tb.Helper()
	prng := pcg.NewRandomised()
	ctxs := twoPartyContexts(tb, prng)
	baseReceiverOut, baseSenderOut := syntheticBaseOTs(tb, prng, kappa)
	s, err := softspoken.NewSender(ctxs[extSenderID], baseReceiverOut)
	require.NoError(tb, err)
	r, err := softspoken.NewReceiver(ctxs[extReceiverID], baseSenderOut, prng)
	require.NoError(tb, err)
	return ctxs, s, r
}

func bit(packed []byte, i int) byte { return (packed[i/8] >> (i % 8)) & 0b1 }

// checkRandomOT verifies the random OT relation: the receiver holds exactly the
// sender's message selected by its choice bit, for every OT.
func checkRandomOT(tb testing.TB, l int, senderOut *ot.SenderOutput[softspoken.Message], receiverOut *ot.ReceiverOutput[softspoken.Message]) {
	tb.Helper()
	require.Equal(tb, l, senderOut.InferredL())
	require.Equal(tb, l, receiverOut.InferredL())
	choices := receiverOut.Choices()
	for j := range l {
		cj := bit(choices, j)
		require.Equal(tb, senderOut.Messages()[j][cj], receiverOut.Messages()[j], "OT %d", j)
		require.NotEqual(tb, senderOut.Messages()[j][1-cj], receiverOut.Messages()[j], "OT %d", j)
		if j > 0 {
			require.NotEqual(tb, senderOut.Messages()[j-1][0], senderOut.Messages()[j][0])
		}
	}
}

func requireTranscriptsMatch(tb testing.TB, ctxs map[sharing.ID]*session.Context) {
	tb.Helper()
	senderTape, err := ctxs[extSenderID].Transcript().ExtractBytes("after", 32)
	require.NoError(tb, err)
	receiverTape, err := ctxs[extReceiverID].Transcript().ExtractBytes("after", 32)
	require.NoError(tb, err)
	require.Equal(tb, senderTape, receiverTape, "transcripts must stay consistent")
}

func TestExtend_SyntheticBaseOTs(t *testing.T) {
	t.Parallel()
	ctxs, s, r := fixture(t)

	var previous *ot.SenderOutput[softspoken.Message]
	for _, l := range []int{512, 128} {
		receiverOut, extend, err := r.Extend(l)
		require.NoError(t, err)
		senderOut, err := s.Extend(ntu.CBORRoundTrip(t, extend))
		require.NoError(t, err)
		checkRandomOT(t, l, senderOut, receiverOut)
		if previous != nil {
			require.NotEqual(t, previous.Messages()[0], senderOut.Messages()[0], "later extensions give fresh OTs")
		}
		previous = senderOut
	}
	requireTranscriptsMatch(t, ctxs)
}

func TestExtend_OnMRR21BaseOTs(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	ctxs := twoPartyContexts(t, prng)
	curve := k256.NewCurve()

	baseReceiver, err := mrr21.NewReceiver[iknp03.Seed](ctxs[extSenderID], curve, kappa, prng)
	require.NoError(t, err)
	baseSender, err := mrr21.NewSender[iknp03.Seed](ctxs[extReceiverID], curve, kappa, prng)
	require.NoError(t, err)
	baseSenderMsg, err := baseSender.Round1()
	require.NoError(t, err)
	baseReceiverMsg, err := baseReceiver.Round1(randomBytes(t, prng, kappa/8))
	require.NoError(t, err)
	baseSenderOut, err := baseSender.Round2(ntu.CBORRoundTrip(t, baseReceiverMsg))
	require.NoError(t, err)
	baseReceiverOut, err := baseReceiver.Round2(ntu.CBORRoundTrip(t, baseSenderMsg))
	require.NoError(t, err)

	s, err := softspoken.NewSender(ctxs[extSenderID], baseReceiverOut)
	require.NoError(t, err)
	r, err := softspoken.NewReceiver(ctxs[extReceiverID], baseSenderOut, prng)
	require.NoError(t, err)

	const l = 1024
	receiverOut, extend, err := r.Extend(l)
	require.NoError(t, err)
	senderOut, err := s.Extend(ntu.CBORRoundTrip(t, extend))
	require.NoError(t, err)
	checkRandomOT(t, l, senderOut, receiverOut)
	requireTranscriptsMatch(t, ctxs)
}

// TestOneRoundTripFlow runs base OTs and one extension in a single round trip,
// as in the IKNP03 test: A sends φ, B replies with m_S and the extension
// message, A verifies and finishes.
func TestOneRoundTripFlow(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()
	ctxs := twoPartyContexts(t, prng)
	curve := k256.NewCurve()
	const l = 512

	baseReceiver, err := mrr21.NewReceiver[iknp03.Seed](ctxs[extSenderID], curve, kappa, prng)
	require.NoError(t, err)
	phis, err := baseReceiver.Round1(randomBytes(t, prng, kappa/8))
	require.NoError(t, err)

	baseSender, err := mrr21.NewSender[iknp03.Seed](ctxs[extReceiverID], curve, kappa, prng)
	require.NoError(t, err)
	ms, err := baseSender.Round1()
	require.NoError(t, err)
	baseSenderOut, err := baseSender.Round2(ntu.CBORRoundTrip(t, phis))
	require.NoError(t, err)
	extReceiver, err := softspoken.NewReceiver(ctxs[extReceiverID], baseSenderOut, prng)
	require.NoError(t, err)
	receiverOut, extend, err := extReceiver.Extend(l)
	require.NoError(t, err)

	baseReceiverOut, err := baseReceiver.Round2(ntu.CBORRoundTrip(t, ms))
	require.NoError(t, err)
	extSender, err := softspoken.NewSender(ctxs[extSenderID], baseReceiverOut)
	require.NoError(t, err)
	senderOut, err := extSender.Extend(ntu.CBORRoundTrip(t, extend))
	require.NoError(t, err)

	checkRandomOT(t, l, senderOut, receiverOut)
	requireTranscriptsMatch(t, ctxs)
}

func TestConsistencyCheckRejectsTampering(t *testing.T) {
	t.Parallel()
	one := bf128.NewField().One()

	for name, tamper := range map[string]func(*message){
		"x response": func(m *message) { m.XResponse = m.XResponse.Add(one) },
		"t response": func(m *message) { m.TResponse[5] = m.TResponse[5].Add(one) },
		// Flipping a bit of every column changes q_i wherever Δ_i = 1, so the
		// check fails unless Δ = 0, which has probability 2^-128.
		"cote columns": func(m *message) {
			for i := range m.COTEMessage.U {
				m.COTEMessage.U[i][0] ^= 1
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, s, r := fixture(t)
			_, extend, err := r.Extend(256)
			require.NoError(t, err)
			tamper(extend)
			_, err = s.Extend(extend)
			require.ErrorIs(t, err, base.ErrAbort)
			require.True(t, base.ShouldAbort(err))
			require.Equal(t, []sharing.ID{extReceiverID}, base.GetMaliciousIdentities[sharing.ID](err))

			// The sender's PRGs and transcript have moved past the receiver's, so it
			// refuses to continue, with a valid message as much as with the bad one.
			_, err = s.Extend(extend)
			require.ErrorIs(t, err, ot.ErrRound)
			_, fresh, err := r.Extend(256)
			require.NoError(t, err)
			_, err = s.Extend(fresh)
			require.ErrorIs(t, err, ot.ErrRound)
		})
	}
}

func TestValidation(t *testing.T) {
	t.Parallel()

	t.Run("constructor and extend arguments", func(t *testing.T) {
		t.Parallel()
		prng := pcg.NewRandomised()
		ctxs := twoPartyContexts(t, prng)
		baseReceiverOut, baseSenderOut := syntheticBaseOTs(t, prng, kappa)
		_, err := softspoken.NewReceiver(ctxs[extReceiverID], baseSenderOut, nil)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
		_, err = softspoken.NewReceiver(ctxs[extReceiverID], nil, prng)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
		_, err = softspoken.NewSender(nil, baseReceiverOut)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
		_, err = softspoken.NewSender(ctxs[extSenderID], nil)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)

		// κ is fixed to 128 by the message type, so 64 base OTs are rejected.
		fewReceiverOut, fewSenderOut := syntheticBaseOTs(t, prng, 64)
		_, err = softspoken.NewSender(ctxs[extSenderID], fewReceiverOut)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
		_, err = softspoken.NewReceiver(ctxs[extReceiverID], fewSenderOut, prng)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)

		r, err := softspoken.NewReceiver(ctxs[extReceiverID], baseSenderOut, prng)
		require.NoError(t, err)
		for _, l := range []int{0, 64, 100, -128, iknp03.MaxExtension} {
			_, _, err = r.Extend(l)
			require.ErrorIs(t, err, ot.ErrInvalidArgument, "l = %d", l)
		}
	})

	t.Run("sender rejects malformed messages", func(t *testing.T) {
		t.Parallel()
		_, s, r := fixture(t)
		_, extend, err := r.Extend(256)
		require.NoError(t, err)

		_, err = s.Extend(nil)
		require.ErrorIs(t, err, ot.ErrInvalidArgument)
		_, err = s.Extend(&message{COTEMessage: nil, XResponse: extend.XResponse, TResponse: extend.TResponse})
		require.ErrorIs(t, err, ot.ErrValidation)
		_, err = s.Extend(&message{COTEMessage: extend.COTEMessage, XResponse: nil, TResponse: extend.TResponse})
		require.ErrorIs(t, err, ot.ErrValidation)
		_, err = s.Extend(&message{COTEMessage: extend.COTEMessage, XResponse: extend.XResponse, TResponse: extend.TResponse[:kappa-1]})
		require.ErrorIs(t, err, ot.ErrValidation)
		withNil := append(extend.TResponse[:kappa-1:kappa-1], nil)
		_, err = s.Extend(&message{COTEMessage: extend.COTEMessage, XResponse: extend.XResponse, TResponse: withNil})
		require.ErrorIs(t, err, ot.ErrValidation)
		short := &iknp03.RoundExtendP2P[softspoken.Message]{U: make([][]byte, kappa)}
		for i := range short.U {
			short.U[i] = make([]byte, 16) // ℓ' = 128 < 2·sigma
		}
		_, err = s.Extend(&message{COTEMessage: short, XResponse: extend.XResponse, TResponse: extend.TResponse})
		require.ErrorIs(t, err, ot.ErrValidation)
		require.ErrorIs(t, extend.Validate(s, extSenderID), ot.ErrValidation)
		require.NoError(t, extend.Validate(s, extReceiverID))
	})

	t.Run("message CBOR", func(t *testing.T) {
		t.Parallel()
		_, _, r := fixture(t)
		_, extend, err := r.Extend(128)
		require.NoError(t, err)
		decoded := ntu.CBORRoundTrip(t, extend)
		require.True(t, extend.XResponse.Equal(decoded.XResponse))
		require.Len(t, decoded.TResponse, kappa)
		require.Equal(t, extend.COTEMessage.U, decoded.COTEMessage.U)

		var bad message
		require.ErrorIs(t, cbor.Unmarshal(mustMarshal(t, struct {
			X int `cbor:"x"`
		}{X: 1}), &bad), ot.ErrSerialisation)
		require.ErrorIs(t, cbor.Unmarshal(mustMarshal(t, struct {
			X []byte   `cbor:"x"`
			T [][]byte `cbor:"t"`
		}{X: make([]byte, 15), T: nil}), &bad), ot.ErrInvalidArgument)
	})
}

func mustMarshal(tb testing.TB, v any) []byte {
	tb.Helper()
	data, err := cbor.Marshal(v)
	require.NoError(tb, err)
	return data
}
