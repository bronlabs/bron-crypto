package schnorr_test

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
)

var supportedCurve = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
	edwards25519.NewCurve(),
	pasta.NewPallasCurve(),
	pasta.NewVestaCurve(),
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

			protocol, err := schnorr.NewSigmaProtocol(base, crand.Reader)
			require.NoError(t, err)

			witness, err := curve.ScalarField().Random(crand.Reader)
			require.NoError(t, err)
			statement := base.ScalarMul(witness)

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

			protocol, err := schnorr.NewSigmaProtocol(base, crand.Reader)
			require.NoError(t, err)

			witness, err := curve.ScalarField().Random(crand.Reader)
			require.NoError(t, err)
			statement, err := curve.Random(crand.Reader)
			require.NoError(t, err)

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

			protocol, err := schnorr.NewSigmaProtocol(base, crand.Reader)
			require.NoError(t, err)

			statement, err := curve.Random(crand.Reader)
			require.NoError(t, err)

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
