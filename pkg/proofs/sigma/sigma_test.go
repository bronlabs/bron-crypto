package sigma_test

import (
	"bytes"
	crand "crypto/rand"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/p256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/pallas"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/dlog/batch_schnorr"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts/hagrid"
)

var supportedCurve = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
	edwards25519.NewCurve(),
	pallas.NewCurve(),
	bls12381.NewG1(),
	bls12381.NewG2(),
}

func Test_HappyPathSchnorr(t *testing.T) {
	t.Parallel()

	for i, c := range supportedCurve {
		i := i
		curve := c
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			w, err := curve.ScalarField().Random(crand.Reader)
			require.NoError(t, err)
			witness := schnorr.Witness(w)
			statement := schnorr.Statement(curve.ScalarBaseMult(witness))
			prng := crand.Reader
			protocol, err := schnorr.NewSigmaProtocol(curve.Generator(), prng)
			require.NoError(t, err)
			sessionId := []byte("some_session_id_for_test" + strconv.Itoa(i))
			transcript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
			proverTranscript := transcript.Clone()
			verifierTranscript := transcript.Clone()

			prover, err := sigma.NewProver(sessionId, proverTranscript, protocol, statement, witness)
			require.NoError(t, err)
			verifier, err := sigma.NewVerifier(sessionId, verifierTranscript, protocol, statement, prng)
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

			proverBytes, err := proverTranscript.ExtractBytes("test"+strconv.Itoa(i), 32)
			require.NoError(t, err)
			verifierBytes, err := verifierTranscript.ExtractBytes("test"+strconv.Itoa(i), 32)
			require.NoError(t, err)
			require.True(t, bytes.Equal(proverBytes, verifierBytes))
		})
	}
}

func Test_HappyPathBatchSchnorr(t *testing.T) {
	t.Parallel()

	for i, c := range supportedCurve {
		i := i
		curve := c
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			n := 64
			witness := make([]curves.Scalar, n)
			statement := make([]curves.Point, n)
			for j := 0; j < 64; j++ {
				var err error
				witness[j], err = curve.ScalarField().Random(crand.Reader)
				require.NoError(t, err)
				statement[j] = curve.ScalarBaseMult(witness[j])
			}

			prng := crand.Reader
			protocol, err := batch_schnorr.NewSigmaProtocol(curve.Generator(), prng)
			require.NoError(t, err)
			sessionId := []byte("some_session_id_for_test" + strconv.Itoa(i))
			transcript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
			proverTranscript := transcript.Clone()
			verifierTranscript := transcript.Clone()

			prover, err := sigma.NewProver(sessionId, proverTranscript, protocol, statement, witness)
			require.NoError(t, err)
			verifier, err := sigma.NewVerifier(sessionId, verifierTranscript, protocol, statement, prng)
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

			proverBytes, err := proverTranscript.ExtractBytes("test"+strconv.Itoa(i), 32)
			require.NoError(t, err)
			verifierBytes, err := verifierTranscript.ExtractBytes("test"+strconv.Itoa(i), 32)
			require.NoError(t, err)
			require.True(t, bytes.Equal(proverBytes, verifierBytes))
		})
	}
}
