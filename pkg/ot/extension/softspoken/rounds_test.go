package softspoken_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	const KAPPA = 128
	const XI = 2048
	const L = 256
	prng := crand.Reader

	// generate seeds
	receiverSeeds := &vsot.ReceiverOutput{
		Choices:  make([]byte, KAPPA/8),
		Messages: make([][][]byte, KAPPA),
	}
	senderSeeds := &vsot.SenderOutput{
		Messages: make([][2][][]byte, KAPPA),
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
		require.Equal(t, len(receiverSeeds.Choices)*8, KAPPA)
		require.Len(t, receiverSeeds.Messages, KAPPA)
		require.Len(t, senderSeeds.Messages, KAPPA)

		for i := range KAPPA {
			choice := (receiverSeeds.Choices[i/8] >> (i % 8)) & 0b1
			for j := range 1 {
				require.Len(t, senderSeeds.Messages[i][0][j], 32)
				require.Len(t, senderSeeds.Messages[i][1][j], 32)
				require.Equal(t, senderSeeds.Messages[i][choice][j], receiverSeeds.Messages[i][j])
				require.NotEqual(t, senderSeeds.Messages[i][1-choice][j], receiverSeeds.Messages[i][j])
			}
		}
	})

	var sessionId network.SID
	_, err = io.ReadFull(prng, sessionId[:])
	require.NoError(t, err)
	hashFunc := sha256.New
	suite, err := softspoken.NewSuite(XI, L, hashFunc)
	require.NoError(t, err)
	tape := hagrid.NewTranscript("test")

	receiverTape := tape.Clone()
	receiver, err := softspoken.NewReceiver(sessionId, senderSeeds, suite, receiverTape, prng)
	require.NoError(t, err)
	choices := make([]byte, XI/8)
	_, err = io.ReadFull(prng, choices)
	require.NoError(t, err)
	r1, receiverOutput, err := receiver.Round1(choices)
	require.NoError(t, err)

	senderTape := tape.Clone()
	sender, err := softspoken.NewSender(sessionId, receiverSeeds, suite, senderTape, prng)
	require.NoError(t, err)
	senderOutput, err := sender.Round2(r1)
	require.NoError(t, err)

	t.Run("messages match", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, receiverOutput.Choices, choices)
		require.Equal(t, len(receiverOutput.Choices)*8, XI)
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
