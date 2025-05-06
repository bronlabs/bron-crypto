package fiatshamir_test

import (
	"bytes"
	crand "crypto/rand"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/simple"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	fiatShamir "github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
)

//func Test_HappyPathWithBatchSchnorr(t *testing.T) {
//	t.Parallel()
//
//	for i, c := range supportedCurve {
//		i := i
//		curve := c
//		t.Run(curve.Name(), func(t *testing.T) {
//			t.Parallel()
//
//			n := 16
//			prng := crand.Reader
//			sessionId := []byte("TestSessionId" + strconv.Itoa(i))
//
//			schnorrProtocol, err := batch_schnorr.NewSigmaProtocol(uint(n), curve.Generator(), prng)
//			require.NoError(t, err)
//
//			nizk, err := fiatShamir.NewCompiler(schnorrProtocol)
//			require.NoError(t, err)
//
//			proverTranscript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
//			prover, err := nizk.NewProver(sessionId, proverTranscript)
//			require.NoError(t, err)
//			require.NotNil(t, prover)
//
//			verifierTranscript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
//			verifier, err := nizk.NewVerifier(sessionId, verifierTranscript)
//			require.NoError(t, err)
//			require.NotNil(t, verifier)
//
//			witness := make([]curves.Scalar, n)
//			statement := make([]curves.Point, n)
//			for j := 0; j < n; j++ {
//				witness[j], err = curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				statement[j] = curve.ScalarBaseMult(witness[j])
//			}
//
//			proof, err := prover.Prove(statement, witness)
//			require.NoError(t, err)
//
//			err = verifier.Verify(statement, proof)
//			require.NoError(t, err)
//
//			proverBytes, err := proverTranscript.ExtractBytes("Bytes"+strconv.Itoa(i), 32)
//			require.NoError(t, err)
//			verifierBytes, err := verifierTranscript.ExtractBytes("Bytes"+strconv.Itoa(i), 32)
//			require.NoError(t, err)
//
//			require.True(t, bytes.Equal(proverBytes, verifierBytes))
//		})
//	}
//}

func Test_HappyPathWithSchnorr(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testHappyPathWithSchnorr(t, curve)
	})
}

//func Test_HappyPathWithChaumPedersen(t *testing.T) {
//	t.Parallel()
//
//	for i, c := range supportedCurve {
//		i := i
//		curve := c
//		t.Run(curve.Name(), func(t *testing.T) {
//			t.Parallel()
//
//			prng := crand.Reader
//			sessionId := []byte("TestSessionId" + strconv.Itoa(i))
//
//			g1, err := curve.Random(prng)
//			require.NoError(t, err)
//			g2, err := curve.Random(prng)
//			require.NoError(t, err)
//
//			schnorrProtocol, err := chaum.NewSigmaProtocol(g1, g2, prng)
//			require.NoError(t, err)
//
//			nizk, err := fiatShamir.NewCompiler(schnorrProtocol)
//			require.NoError(t, err)
//
//			proverTranscript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
//			prover, err := nizk.NewProver(sessionId, proverTranscript)
//			require.NoError(t, err)
//			require.NotNil(t, prover)
//
//			verifierTranscript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
//			verifier, err := nizk.NewVerifier(sessionId, verifierTranscript)
//			require.NoError(t, err)
//			require.NotNil(t, verifier)
//
//			witness, err := curve.ScalarField().Random(prng)
//			require.NoError(t, err)
//			statement := &chaum.Statement{
//				X1: g1.ScalarMul(witness),
//				X2: g2.ScalarMul(witness),
//			}
//
//			proof, err := prover.Prove(statement, witness)
//			require.NoError(t, err)
//
//			err = verifier.Verify(statement, proof)
//			require.NoError(t, err)
//
//			proverBytes, err := proverTranscript.ExtractBytes("Bytes"+strconv.Itoa(i), 32)
//			require.NoError(t, err)
//			verifierBytes, err := verifierTranscript.ExtractBytes("Bytes"+strconv.Itoa(i), 32)
//			require.NoError(t, err)
//
//			require.True(t, bytes.Equal(proverBytes, verifierBytes))
//		})
//	}
//}

func testHappyPathWithSchnorr[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](t *testing.T, curve C) {
	t.Helper()

	prng := crand.Reader
	sessionId := []byte("TestSessionId" + curve.Name())

	schnorrProtocol, err := schnorr.NewSigmaProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	nizk, err := fiatShamir.NewCompiler(schnorrProtocol)
	require.NoError(t, err)

	proverTranscript := simple.NewTranscript("Test" + curve.Name())
	prover, err := nizk.NewProver(sessionId, proverTranscript)
	require.NoError(t, err)
	require.NotNil(t, prover)

	verifierTranscript := simple.NewTranscript("Test" + curve.Name())
	verifier, err := nizk.NewVerifier(sessionId, verifierTranscript)
	require.NoError(t, err)
	require.NotNil(t, verifier)

	w, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	x := curve.Generator().ScalarMul(w)

	witness := schnorr.NewWitness(w)
	statement := schnorr.NewStatement(x)

	proof, err := prover.Prove(statement, witness)
	require.NoError(t, err)

	err = verifier.Verify(statement, proof)
	require.NoError(t, err)

	proverBytes, err := proverTranscript.ExtractBytes("Bytes"+curve.Name(), 32)
	require.NoError(t, err)
	verifierBytes, err := verifierTranscript.ExtractBytes("Bytes"+curve.Name(), 32)
	require.NoError(t, err)

	require.True(t, bytes.Equal(proverBytes, verifierBytes))

}
