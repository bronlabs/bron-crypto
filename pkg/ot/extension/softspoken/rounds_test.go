package softspoken_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	const KAPPA = softspoken.Kappa
	const XI = 2048
	const L = 16
	prng := crand.Reader

	// generate seeds
	receiverSeeds := &vsot.ReceiverOutput{
		ot.ReceiverOutput[[]byte]{
			Choices:  make([]byte, KAPPA/8),
			Messages: make([][][]byte, KAPPA),
		},
	}
	senderSeeds := &vsot.SenderOutput{
		ot.SenderOutput[[]byte]{
			Messages: make([][2][][]byte, KAPPA),
		},
	}
	_, err := io.ReadFull(prng, receiverSeeds.Choices)
	require.NoError(t, err)
	for i := range KAPPA {
		m0 := make([]byte, 32)
		_, err := io.ReadFull(prng, m0)
		require.NoError(t, err)
		m1 := make([]byte, 32)
		_, err = io.ReadFull(prng, m1)
		require.NoError(t, err)
		c := (receiverSeeds.Choices[i/8] >> (i % 8)) & 0b1
		senderSeeds.Messages[i][0] = [][]byte{m0}
		senderSeeds.Messages[i][1] = [][]byte{m1}
		receiverSeeds.Messages[i] = senderSeeds.Messages[i][c]
	}

	// just in case, check
	t.Run("seeds match", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, KAPPA, senderSeeds.InferredXi())
		require.Equal(t, 1, senderSeeds.InferredL())
		require.Equal(t, 32, senderSeeds.InferredMessageBytesLen())
		require.Equal(t, KAPPA, receiverSeeds.InferredXi())
		require.Equal(t, 1, receiverSeeds.InferredL())
		require.Equal(t, 32, receiverSeeds.InferredMessageBytesLen())

		for i := range KAPPA {
			choice := (receiverSeeds.Choices[i/8] >> (i % 8)) & 0b1
			for j := range 1 {
				require.Equal(t, senderSeeds.Messages[i][choice][j], receiverSeeds.Messages[i][j])
				require.NotEqual(t, senderSeeds.Messages[i][1-choice][j], receiverSeeds.Messages[i][j])
			}
		}
	})

	var sessionID network.SID
	_, err = io.ReadFull(prng, sessionID[:])
	require.NoError(t, err)
	hashFunc := sha256.New
	suite, err := softspoken.NewSuite(XI, L, hashFunc)
	require.NoError(t, err)
	tape := hagrid.NewTranscript("test")

	receiverTape := tape.Clone()
	receiver, err := softspoken.NewReceiver(sessionID, senderSeeds, suite, receiverTape, prng)
	require.NoError(t, err)
	choices := make([]byte, XI/8)
	_, err = io.ReadFull(prng, choices)
	require.NoError(t, err)
	r1, receiverOutput, err := receiver.Round1(choices)
	require.NoError(t, err)

	senderTape := tape.Clone()
	sender, err := softspoken.NewSender(sessionID, receiverSeeds, suite, senderTape, prng)
	require.NoError(t, err)
	senderOutput, err := sender.Round2(r1)
	require.NoError(t, err)

	t.Run("messages match", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, receiverOutput.Choices, choices)
		require.Equal(t, XI, len(receiverOutput.Choices)*8)
		require.Len(t, receiverOutput.Messages, XI)
		require.Len(t, senderOutput.Messages, XI)

		for i := range XI {
			choice := (receiverOutput.Choices[i/8] >> (i % 8)) & 0b1
			for j := range L {
				require.Len(t, senderOutput.Messages[i][choice][j], hashFunc().Size())
				require.Len(t, senderOutput.Messages[i][1-choice][j], hashFunc().Size())
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
