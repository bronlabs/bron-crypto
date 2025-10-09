package rvole_bbot_test

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/network"
	rvole_bbot "github.com/bronlabs/bron-crypto/pkg/threshold/rvole/bbot"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	const L = 8
	prng := crand.Reader
	curve := k256.NewCurve()
	var sessionID network.SID
	_, err := io.ReadFull(prng, sessionID[:])
	require.NoError(t, err)
	tape := hagrid.NewTranscript("test")
	suite, err := rvole_bbot.NewSuite(L, curve)
	require.NoError(t, err)

	aliceTape := tape.Clone()
	alice, err := rvole_bbot.NewAlice(sessionID, suite, prng, aliceTape)
	require.NoError(t, err)

	bobTape := tape.Clone()
	bob, err := rvole_bbot.NewBob(sessionID, suite, prng, bobTape)
	require.NoError(t, err)

	r1, err := alice.Round1()
	require.NoError(t, err)

	r2, b, err := bob.Round2(r1)
	require.NoError(t, err)

	a := make([]*k256.Scalar, L)
	for i := range a {
		a[i], err = k256.NewScalarField().Random(prng)
		require.NoError(t, err)
	}
	r3, c, err := alice.Round3(r2, a)
	require.NoError(t, err)

	d, err := bob.Round4(r3)
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
