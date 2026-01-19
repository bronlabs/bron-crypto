package vsot_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	const XI = 128
	const L = 1
	prng := crand.Reader
	var sessionID network.SID
	_, err := io.ReadFull(prng, sessionID[:])
	require.NoError(t, err)
	curve := k256.NewCurve()
	hashFunc := sha256.New
	suite, err := vsot.NewSuite(XI, L, curve, hashFunc)
	require.NoError(t, err)

	choices := make([]byte, XI/8)
	_, err = io.ReadFull(prng, choices)
	require.NoError(t, err)

	senderTape := hagrid.NewTranscript("test")
	receiverTape := senderTape.Clone()
	sender, err := vsot.NewSender(sessionID, suite, senderTape, prng)
	require.NoError(t, err)
	receiver, err := vsot.NewReceiver(sessionID, suite, receiverTape, prng)
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

		require.Equal(t, XI, senderOutput.InferredXi())
		require.Equal(t, L, senderOutput.InferredL())
		require.Equal(t, senderOutput.InferredMessageBytesLen(), hashFunc().Size())

		require.Equal(t, receiverOutput.Choices, choices)
		require.Equal(t, XI, receiverOutput.InferredXi())
		require.Equal(t, L, receiverOutput.InferredL())
		require.Equal(t, receiverOutput.InferredMessageBytesLen(), hashFunc().Size())

		for i := range XI {
			choice := (receiverOutput.Choices[i/8] >> (i % 8)) & 0b1
			for j := range L {
				require.Equal(t, senderOutput.Messages[i][choice][j], receiverOutput.Messages[i][j])
				require.NotEqual(t, senderOutput.Messages[i][1-choice][j], receiverOutput.Messages[i][j])
			}
		}
	})

	t.Run("transcripts match", func(t *testing.T) {
		t.Parallel()
		senderBytes, err := senderTape.ExtractBytes("test", 32)
		require.NoError(t, err)
		receiverBytes, err := receiverTape.ExtractBytes("test", 32)
		require.NoError(t, err)
		require.Equal(t, senderBytes, receiverBytes)
	})
}
