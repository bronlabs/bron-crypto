package rvole_softspoken_test

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
	rvole_softspoken "github.com/bronlabs/bron-crypto/pkg/threshold/rvole/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	const L = 16
	prng := crand.Reader
	var sessionID network.SID
	_, err := io.ReadFull(prng, sessionID[:])
	require.NoError(t, err)

	curve := k256.NewCurve()
	hashFunc := sha256.New
	suite, err := rvole_softspoken.NewSuite(L, curve, hashFunc)
	require.NoError(t, err)
	tape := hagrid.NewTranscript("test")
	senderSeeds, receiverSeeds := generateSeeds(t, prng)

	aliceTape := tape.Clone()
	alice, err := rvole_softspoken.NewAlice(sessionID, suite, receiverSeeds, prng, aliceTape)
	require.NoError(t, err)

	bobTape := tape.Clone()
	bob, err := rvole_softspoken.NewBob(sessionID, suite, senderSeeds, prng, bobTape)
	require.NoError(t, err)

	r1, b, err := bob.Round1()
	require.NoError(t, err)

	a := make([]*k256.Scalar, L)
	for i := range a {
		a[i], err = k256.NewScalarField().Random(prng)
		require.NoError(t, err)
	}
	r2, c, err := alice.Round2(testutils.CBORRoundTrip(t, r1), a)
	require.NoError(t, err)

	d, err := bob.Round3(testutils.CBORRoundTrip(t, r2))
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
		aliceBytes, err := aliceTape.ExtractBytes("test", 32)
		require.NoError(t, err)
		bobBytes, err := bobTape.ExtractBytes("test", 32)
		require.NoError(t, err)
		require.True(t, bytes.Equal(aliceBytes, bobBytes))
	})
}

func generateSeeds(tb testing.TB, prng io.Reader) (senderSeeds *vsot.SenderOutput, receiverSeeds *vsot.ReceiverOutput) {
	receiverSeeds = &vsot.ReceiverOutput{
		ot.ReceiverOutput[[]byte]{
			Choices:  make([]byte, softspoken.Kappa/8),
			Messages: make([][][]byte, softspoken.Kappa),
		},
	}
	senderSeeds = &vsot.SenderOutput{
		ot.SenderOutput[[]byte]{
			Messages: make([][2][][]byte, softspoken.Kappa),
		},
	}
	_, err := io.ReadFull(prng, receiverSeeds.Choices)
	require.NoError(tb, err)
	for i := range softspoken.Kappa {
		m0 := make([]byte, 32)
		_, err := io.ReadFull(prng, m0)
		require.NoError(tb, err)
		m1 := make([]byte, 32)
		_, err = io.ReadFull(prng, m1)
		require.NoError(tb, err)
		c := (receiverSeeds.Choices[i/8] >> (i % 8)) & 0b1
		senderSeeds.Messages[i][0] = [][]byte{m0}
		senderSeeds.Messages[i][1] = [][]byte{m1}
		receiverSeeds.Messages[i] = senderSeeds.Messages[i][c]
	}

	return senderSeeds, receiverSeeds
}
