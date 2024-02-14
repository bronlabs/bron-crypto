package sigmaAnd_test

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma"
	sigmaCompose "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compose/and"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

func Test_SchnorrAndSchnorr(t *testing.T) {
	t.Parallel()

	var supportedCurves = []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
		edwards25519.NewCurve(),
		pallas.NewCurve(),
		bls12381.NewG1(),
		bls12381.NewG2(),
	}

	for i, c := range supportedCurves {
		i := i
		curve := c
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			prng := crand.Reader
			sigma0, err := schnorr.NewSigmaProtocol(curve.Generator(), prng)
			require.NoError(t, err)
			sigma1, err := schnorr.NewSigmaProtocol(curve.Generator(), prng)
			require.NoError(t, err)

			andProtocol := sigmaCompose.SigmaAnd(sigma0, sigma1)
			require.NoError(t, err)
			sessionId := []byte("some_session_id_for_test" + strconv.Itoa(i))
			transcript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
			proverTranscript := transcript.Clone()
			verifierTranscript := transcript.Clone()

			w0, err := curve.ScalarField().Random(crand.Reader)
			require.NoError(t, err)
			w1, err := curve.ScalarField().Random(crand.Reader)
			require.NoError(t, err)

			x0 := curve.ScalarBaseMult(w0)
			x1 := curve.ScalarBaseMult(w1)

			t.Run("both true", func(t *testing.T) {
				w0 := schnorr.Witness(w0)
				w1 := schnorr.Witness(w1)
				x0 := schnorr.Statement(x0)
				x1 := schnorr.Statement(x1)

				statement := sigmaCompose.StatementAnd(x0, x1)
				witness := sigmaCompose.WitnessAnd(w0, w1)

				prover, err := sigma.NewProver(sessionId, proverTranscript, andProtocol, statement, witness)
				require.NoError(t, err)
				verifier, err := sigma.NewVerifier(sessionId, verifierTranscript, andProtocol, statement, prng)
				require.NoError(t, err)

				// round 1
				commitment, err := prover.Round1()
				require.NoError(t, err)

				// round 2
				challenge, err := verifier.Round2(commitment)
				require.NoError(t, err)

				// round 3
				response, err := prover.Round3(challenge)
				require.NoError(t, err)

				// verify
				accepted := verifier.Verify(response)
				require.NoError(t, accepted)
			})

			t.Run("first true, second false", func(t *testing.T) {
				w0 := schnorr.Witness(w0)
				w1 := schnorr.Witness(w1)
				x0 := schnorr.Statement(x0)
				randomPoint, err := curve.Random(prng)
				require.NoError(t, err)
				x1 := schnorr.Statement(randomPoint)

				statement := sigmaCompose.StatementAnd(x0, x1)
				witness := sigmaCompose.WitnessAnd(w0, w1)

				prover, err := sigma.NewProver(sessionId, proverTranscript, andProtocol, statement, witness)
				require.NoError(t, err)
				verifier, err := sigma.NewVerifier(sessionId, verifierTranscript, andProtocol, statement, prng)
				require.NoError(t, err)

				// round 1
				commitment, err := prover.Round1()
				require.NoError(t, err)

				// round 2
				challenge, err := verifier.Round2(commitment)
				require.NoError(t, err)

				// round 3
				response, err := prover.Round3(challenge)
				require.NoError(t, err)

				// verify
				accepted := verifier.Verify(response)
				require.Error(t, accepted)
			})

			t.Run("first false, second true", func(t *testing.T) {
				w0 := schnorr.Witness(w0)
				w1 := schnorr.Witness(w1)

				randomPoint, err := curve.Random(prng)
				require.NoError(t, err)
				x0 := schnorr.Statement(randomPoint)
				x1 := schnorr.Statement(x1)

				statement := sigmaCompose.StatementAnd(x0, x1)
				witness := sigmaCompose.WitnessAnd(w0, w1)

				prover, err := sigma.NewProver(sessionId, proverTranscript, andProtocol, statement, witness)
				require.NoError(t, err)
				verifier, err := sigma.NewVerifier(sessionId, verifierTranscript, andProtocol, statement, prng)
				require.NoError(t, err)

				// round 1
				commitment, err := prover.Round1()
				require.NoError(t, err)

				// round 2
				challenge, err := verifier.Round2(commitment)
				require.NoError(t, err)

				// round 3
				response, err := prover.Round3(challenge)
				require.NoError(t, err)

				// verify
				accepted := verifier.Verify(response)
				require.Error(t, accepted)
			})

			t.Run("both false", func(t *testing.T) {
				w0 := schnorr.Witness(w0)
				w1 := schnorr.Witness(w1)

				randomPoint, err := curve.Random(prng)
				require.NoError(t, err)
				x0 := schnorr.Statement(randomPoint)
				randomPoint, err = curve.Random(prng)
				require.NoError(t, err)
				x1 := schnorr.Statement(randomPoint)

				statement := sigmaCompose.StatementAnd(x0, x1)
				witness := sigmaCompose.WitnessAnd(w0, w1)

				prover, err := sigma.NewProver(sessionId, proverTranscript, andProtocol, statement, witness)
				require.NoError(t, err)
				verifier, err := sigma.NewVerifier(sessionId, verifierTranscript, andProtocol, statement, prng)
				require.NoError(t, err)

				// round 1
				commitment, err := prover.Round1()
				require.NoError(t, err)

				// round 2
				challenge, err := verifier.Round2(commitment)
				require.NoError(t, err)

				// round 3
				response, err := prover.Round3(challenge)
				require.NoError(t, err)

				// verify
				accepted := verifier.Verify(response)
				require.Error(t, accepted)
			})

			t.Run("transcript matches", func(t *testing.T) {
				proverBytes, err := proverTranscript.ExtractBytes("test"+strconv.Itoa(i), 32)
				require.NoError(t, err)
				verifierBytes, err := verifierTranscript.ExtractBytes("test"+strconv.Itoa(i), 32)
				require.NoError(t, err)
				require.True(t, bytes.Equal(proverBytes, verifierBytes))
			})
		})
	}
}

func Test_SchnorrAndSchnorrSimulator(t *testing.T) {
	t.Parallel()

	var supportedCurves = []curves.Curve{
		k256.NewCurve(),
		p256.NewCurve(),
		edwards25519.NewCurve(),
		pallas.NewCurve(),
		bls12381.NewG1(),
		bls12381.NewG2(),
	}

	for _, c := range supportedCurves {
		curve := c
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			prng := crand.Reader
			sigma0, err := schnorr.NewSigmaProtocol(curve.Generator(), prng)
			require.NoError(t, err)
			sigma1, err := schnorr.NewSigmaProtocol(curve.Generator(), prng)
			require.NoError(t, err)

			andProtocol := sigmaCompose.SigmaAnd(sigma0, sigma1)
			require.NoError(t, err)

			randomPoint, err := curve.Random(prng)
			require.NoError(t, err)
			x0 := schnorr.Statement(randomPoint)
			randomPoint, err = curve.Random(prng)
			require.NoError(t, err)
			x1 := schnorr.Statement(randomPoint)

			statement := sigmaCompose.StatementAnd(x0, x1)
			challenge := make([]byte, andProtocol.GetChallengeBytesLength())
			_, err = io.ReadFull(prng, challenge)
			require.NoError(t, err)
			commitment, response, err := andProtocol.RunSimulator(statement, challenge)
			require.NoError(t, err)

			accepted := andProtocol.Verify(statement, commitment, challenge, response)
			require.NoError(t, accepted)
		})
	}
}
