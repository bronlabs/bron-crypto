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
			commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
			require.NoError(t, err)

			// round 2
			challenge := make([]byte, protocol.GetChallengeBytesLength())
			_, err = io.ReadFull(crand.Reader, challenge)
			require.NoError(t, err)

			// round 3
			response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
			require.NoError(t, err)

			// verify
			err = protocol.Verify(statement, commitment, challenge, response)
			require.NoError(t, err)
		})
	}
}

func Test_InvalidStatement(t *testing.T) {
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

			t.Run("first invalid", func(t *testing.T) {
				witness, err := curve.ScalarField().Random(crand.Reader)
				require.NoError(t, err)
				x1, err := curve.Random(crand.Reader)
				require.NoError(t, err)
				statement := &new_chaum.Statement{
					X1: x1,
					X2: g2.Mul(witness),
				}

				// round 1
				commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
				require.NoError(t, err)

				// round 2
				challenge := make([]byte, protocol.GetChallengeBytesLength())
				_, err = io.ReadFull(crand.Reader, challenge)
				require.NoError(t, err)

				// round 3
				response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
				require.NoError(t, err)

				// verify
				err = protocol.Verify(statement, commitment, challenge, response)
				require.Error(t, err)
			})

			t.Run("second invalid", func(t *testing.T) {
				witness, err := curve.ScalarField().Random(crand.Reader)
				require.NoError(t, err)
				x2, err := curve.Random(crand.Reader)
				require.NoError(t, err)
				statement := &new_chaum.Statement{
					X1: g1.Mul(witness),
					X2: x2,
				}

				// round 1
				commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
				require.NoError(t, err)

				// round 2
				challenge := make([]byte, protocol.GetChallengeBytesLength())
				_, err = io.ReadFull(crand.Reader, challenge)
				require.NoError(t, err)

				// round 3
				response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
				require.NoError(t, err)

				// verify
				err = protocol.Verify(statement, commitment, challenge, response)
				require.Error(t, err)
			})
		})
	}
}

func Test_Simulator(t *testing.T) {
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

			x1, err := curve.Random(crand.Reader)
			require.NoError(t, err)
			x2, err := curve.Random(crand.Reader)
			require.NoError(t, err)

			statement := &new_chaum.Statement{
				X1: x1,
				X2: x2,
			}

			// simulate
			challenge := make([]byte, protocol.GetChallengeBytesLength())
			_, err = io.ReadFull(crand.Reader, challenge)
			require.NoError(t, err)
			commitment, response, err := protocol.RunSimulator(statement, challenge)
			require.NoError(t, err)

			// verify
			err = protocol.Verify(statement, commitment, challenge, response)
			require.NoError(t, err)
		})
	}
}
