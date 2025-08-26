package vsot_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	const CHI = 8 * 32
	prng := crand.Reader
	var sessionId network.SID
	_, err := io.ReadFull(prng, sessionId[:])
	require.NoError(t, err)
	curve := k256.NewCurve()
	choices := make([]byte, CHI/8)
	_, err = io.ReadFull(prng, choices)
	require.NoError(t, err)

	senderTape := hagrid.NewTranscript("test")
	sender, err := vsot.NewSender(sessionId, CHI, curve, sha256.New, senderTape, prng)
	require.NoError(t, err)
	receiverTape := senderTape.Clone()
	receiver, err := vsot.NewReceiver(sessionId, CHI, curve, sha256.New, receiverTape, prng)
	require.NoError(t, err)

	r1, err := sender.Round1()
	require.NoError(t, err)
	r2, receiverOutput, err := receiver.Round2(r1, choices)
	require.NoError(t, err)
	r3, senderOutput, err := sender.Round3(r2)
	require.NoError(t, err)
	r4, err := receiver.Round4(r3)
	require.NoError(t, err)
	r5, err := sender.Round5(r4)
	require.NoError(t, err)
	err = receiver.Round6(r5)
	require.NoError(t, err)

	t.Run("messages match", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, receiverOutput.Choices, choices)
		require.Equal(t, len(receiverOutput.Choices)*8, CHI)
		require.Len(t, receiverOutput.M, CHI)
		require.Len(t, senderOutput.M, CHI)
		for _, m := range receiverOutput.M {
			require.True(t, len(m) >= 16)
		}
		require.Len(t, senderOutput.M, CHI)
		for _, m := range senderOutput.M {
			require.True(t, len(m[0]) >= 16)
			require.True(t, len(m[1]) >= 16)
		}
		for i := range CHI {
			choice := (receiverOutput.Choices[i/8] >> (i % 8)) & 0b1
			require.Equal(t, senderOutput.M[i][choice], receiverOutput.M[i])
			require.NotEqual(t, senderOutput.M[i][1-choice], receiverOutput.M[i])
		}
	})
	t.Run("transcripts match", func(t *testing.T) {
		senderBytes, err := senderTape.ExtractBytes("test", 32)
		require.NoError(t, err)
		receiverBytes, err := receiverTape.ExtractBytes("test", 32)
		require.NoError(t, err)
		require.Equal(t, senderBytes, receiverBytes)
	})
}
