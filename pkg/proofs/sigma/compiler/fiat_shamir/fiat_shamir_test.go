package fiat_shamir_test

import (
	"bytes"
	crand "crypto/rand"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dleq/new_chaum"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/batch_schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/new_schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/fiat_shamir"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

var supportedCurve = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
	edwards25519.NewCurve(),
	pallas.NewCurve(),
	bls12381.NewG1(),
	bls12381.NewG2(),
}

func Test_HappyPathWithBatchSchnorr(t *testing.T) {
	t.Parallel()

	for i, c := range supportedCurve {
		i := i
		curve := c
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			prng := crand.Reader
			sessionId := []byte("TestSessionId" + strconv.Itoa(i))

			schnorrProtocol, err := batch_schnorr.NewSigmaProtocol(curve.Generator(), prng)
			require.NoError(t, err)

			nizk, err := fiat_shamir.NewCompiler(schnorrProtocol)
			require.NoError(t, err)

			proverTranscript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
			prover, err := nizk.NewProver(sessionId, proverTranscript)
			require.NoError(t, err)
			require.NotNil(t, prover)

			verifierTranscript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
			verifier, err := nizk.NewVerifier(sessionId, verifierTranscript)
			require.NoError(t, err)
			require.NotNil(t, verifier)

			n := 16
			witness := make([]curves.Scalar, n)
			statement := make([]curves.Point, n)
			for j := 0; j < n; j++ {
				witness[j], err = curve.ScalarField().Random(prng)
				require.NoError(t, err)
				statement[j] = curve.ScalarBaseMult(witness[j])
			}

			proof, err := prover.Prove(statement, witness)
			require.NoError(t, err)

			err = verifier.Verify(statement, proof)
			require.NoError(t, err)

			proverBytes, err := proverTranscript.ExtractBytes("Bytes"+strconv.Itoa(i), 32)
			require.NoError(t, err)
			verifierBytes, err := verifierTranscript.ExtractBytes("Bytes"+strconv.Itoa(i), 32)
			require.NoError(t, err)

			require.True(t, bytes.Equal(proverBytes, verifierBytes))
		})
	}
}

func Test_HappyPathWithSchnorr(t *testing.T) {
	t.Parallel()

	for i, c := range supportedCurve {
		i := i
		curve := c
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			prng := crand.Reader
			sessionId := []byte("TestSessionId" + strconv.Itoa(i))

			schnorrProtocol, err := new_schnorr.NewSigmaProtocol(curve.Generator(), prng)
			require.NoError(t, err)

			nizk, err := fiat_shamir.NewCompiler(schnorrProtocol)
			require.NoError(t, err)

			proverTranscript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
			prover, err := nizk.NewProver(sessionId, proverTranscript)
			require.NoError(t, err)
			require.NotNil(t, prover)

			verifierTranscript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
			verifier, err := nizk.NewVerifier(sessionId, verifierTranscript)
			require.NoError(t, err)
			require.NotNil(t, verifier)

			witness, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			statement := curve.ScalarBaseMult(witness)

			proof, err := prover.Prove(statement, witness)
			require.NoError(t, err)

			err = verifier.Verify(statement, proof)
			require.NoError(t, err)

			proverBytes, err := proverTranscript.ExtractBytes("Bytes"+strconv.Itoa(i), 32)
			require.NoError(t, err)
			verifierBytes, err := verifierTranscript.ExtractBytes("Bytes"+strconv.Itoa(i), 32)
			require.NoError(t, err)

			require.True(t, bytes.Equal(proverBytes, verifierBytes))
		})
	}
}

func Test_HappyPathWithChaumPedersen(t *testing.T) {
	t.Parallel()

	for i, c := range supportedCurve {
		i := i
		curve := c
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()

			prng := crand.Reader
			sessionId := []byte("TestSessionId" + strconv.Itoa(i))

			g1, err := curve.Random(prng)
			require.NoError(t, err)
			g2, err := curve.Random(prng)
			require.NoError(t, err)

			schnorrProtocol, err := new_chaum.NewSigmaProtocol(g1, g2, prng)
			require.NoError(t, err)

			nizk, err := fiat_shamir.NewCompiler(schnorrProtocol)
			require.NoError(t, err)

			proverTranscript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
			prover, err := nizk.NewProver(sessionId, proverTranscript)
			require.NoError(t, err)
			require.NotNil(t, prover)

			verifierTranscript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
			verifier, err := nizk.NewVerifier(sessionId, verifierTranscript)
			require.NoError(t, err)
			require.NotNil(t, verifier)

			witness, err := curve.ScalarField().Random(prng)
			require.NoError(t, err)
			statement := &new_chaum.Statement{
				X1: g1.Mul(witness),
				X2: g2.Mul(witness),
			}

			proof, err := prover.Prove(statement, witness)
			require.NoError(t, err)

			err = verifier.Verify(statement, proof)
			require.NoError(t, err)

			proverBytes, err := proverTranscript.ExtractBytes("Bytes"+strconv.Itoa(i), 32)
			require.NoError(t, err)
			verifierBytes, err := verifierTranscript.ExtractBytes("Bytes"+strconv.Itoa(i), 32)
			require.NoError(t, err)

			require.True(t, bytes.Equal(proverBytes, verifierBytes))
		})
	}
}
