package new_chaum_test

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dleq/new_chaum"
)

var supportedCurve = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
	edwards25519.NewCurve(),
	pallas.NewCurve(),
	bls12381.NewG1(),
	bls12381.NewG2(),
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	for _, c := range supportedCurve {
		curve := c
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			g1, err := curve.Random(crand.Reader)
			require.NoError(t, err)
			g2, err := curve.Random(crand.Reader)
			require.NoError(t, err)

			protocol, err := new_chaum.NewSigmaProtocol(g1, g2, crand.Reader)
			require.NoError(t, err)

			witness, err := curve.ScalarField().Random(crand.Reader)
			require.NoError(t, err)
			statement := &new_chaum.Statement{
				X1: g1.Mul(witness),
				X2: g2.Mul(witness),
			}

			// round 1
			commitment, state, err := protocol.GenerateCommitment(statement, witness)
			require.NoError(t, err)

			// round 2
			entropy := make([]byte, 32)
			_, err = io.ReadFull(crand.Reader, entropy)
			require.NoError(t, err)
			challenge, err := protocol.GenerateChallenge(entropy)
			require.NoError(t, err)

			// round 3
			response, err := protocol.GenerateResponse(statement, witness, state, challenge)
			require.NoError(t, err)

			// verify
			err = protocol.Verify(statement, commitment, challenge, response)
			require.NoError(t, err)
		})
	}
}
