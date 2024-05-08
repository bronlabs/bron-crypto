package elgamalcomm_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/comm/elgamalcomm"
)

var supportedCurves = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
	pallas.NewCurve(),
	edwards25519.NewCurve(),
	bls12381.NewG1(),
	bls12381.NewG2(),
}

func TestSimpleHappyPath(t *testing.T) {
	t.Parallel()

	sessionId := []byte("elgamalHappyPathSessionId")
	prng := crand.Reader

	for _, curve := range supportedCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			publicKey, err := curve.Random(crand.Reader)
			require.NoError(t, err)

			c, err := elgamalcomm.NewCommitter(sessionId, publicKey, prng)
			require.NoError(t, err)

			v, err := elgamalcomm.NewVerifier(sessionId, publicKey)
			require.NoError(t, err)

			msg, err := curve.ScalarField().Random(crand.Reader)
			require.NoError(t, err)

			commit, opening, err := c.Commit(curve.Generator().ScalarMul(msg))
			require.NoError(t, err)

			err = v.Verify(commit, opening)
			require.NoError(t, err)
		})
	}
}
