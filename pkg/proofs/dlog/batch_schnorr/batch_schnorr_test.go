package batch_schnorr_test

import (
	crand "crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pallas"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr"
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

			base, err := curve.Random(crand.Reader)
			require.NoError(t, err)
			protocol, err := batch_schnorr.NewSigmaProtocol(base, crand.Reader)
			require.NoError(t, err)

			n := 32
			witness := make([]curves.Scalar, n)
			statement := make([]curves.Point, n)
			for k := 0; k < 32; k++ {
				var err error
				witness[k], err = curve.ScalarField().Random(crand.Reader)
				require.NoError(t, err)
				statement[k] = base.ScalarMul(witness[k])
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

			base, err := curve.Random(crand.Reader)
			require.NoError(t, err)
			protocol, err := batch_schnorr.NewSigmaProtocol(base, crand.Reader)
			require.NoError(t, err)

			n := 16
			witness := make([]curves.Scalar, n)
			statement := make([]curves.Point, n)
			for k := 0; k < n; k++ {
				var err error
				witness[k], err = curve.ScalarField().Random(crand.Reader)
				require.NoError(t, err)
				statement[k] = base.ScalarMul(witness[k])
			}

			for k := 0; k < n; k++ {
				k := k
				t.Run(fmt.Sprintf("invalid %d", k), func(t *testing.T) {
					t.Parallel()

					statementK := make([]curves.Point, n)
					copy(statementK, statement)
					statementK[k], err = curve.Random(crand.Reader)
					require.NoError(t, err)

					// round 1
					commitment, state, err := protocol.ComputeProverCommitment(statementK, witness)
					require.NoError(t, err)

					// round 2
					challenge := make([]byte, protocol.GetChallengeBytesLength())
					_, err = io.ReadFull(crand.Reader, challenge)
					require.NoError(t, err)

					// round 3
					response, err := protocol.ComputeProverResponse(statementK, witness, commitment, state, challenge)
					require.NoError(t, err)

					// verify
					err = protocol.Verify(statementK, commitment, challenge, response)
					require.Error(t, err)
				})
			}
		})
	}
}

func Test_Simulator(t *testing.T) {
	t.Parallel()

	for _, c := range supportedCurve {
		curve := c
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			base, err := curve.Random(crand.Reader)
			require.NoError(t, err)

			protocol, err := batch_schnorr.NewSigmaProtocol(base, crand.Reader)
			require.NoError(t, err)

			n := 16
			statement := make([]curves.Point, n)
			for i := 0; i < n; i++ {
				statement[i], err = curve.Random(crand.Reader)
				require.NoError(t, err)
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
