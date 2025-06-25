package dkls23_bbot_test

import (
	"bytes"
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/mult/dkls23_bbot"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	const L = 8
	prng := crand.Reader
	curve := k256.NewCurve()
	identities, err := testutils.MakeDeterministicTestIdentities(2)
	require.NoError(t, err)
	protocol, err := testutils.MakeProtocol(curve, identities)
	require.NoError(t, err)
	sessionId := []byte("test session id")
	tapes := testutils.MakeTranscripts("test", identities)

	alice, err := dkls23_bbot.NewAlice(identities[0].(types.AuthKey), protocol, sessionId, L, prng, tapes[0])
	require.NoError(t, err)

	bob, err := dkls23_bbot.NewBob(identities[1].(types.AuthKey), protocol, sessionId, L, prng, tapes[1])
	require.NoError(t, err)

	r1, err := alice.Round1()
	require.NoError(t, err)

	r2, b, err := bob.Round2(r1)
	require.NoError(t, err)

	a := make([]curves.Scalar, L)
	for i := range a {
		a[i], err = curve.ScalarField().Random(prng)
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
		aliceBytes, err := tapes[0].ExtractBytes("test", 32)
		require.NoError(t, err)
		bobBytes, err := tapes[1].ExtractBytes("test", 32)
		require.NoError(t, err)
		require.True(t, bytes.Equal(aliceBytes, bobBytes))
	})
}
