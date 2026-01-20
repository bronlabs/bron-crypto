package sigma_test

// import (
// 	"bytes"
// 	crand "crypto/rand"
// 	"testing"

// 	"github.com/bronlabs/bron-crypto/pkg/transcripts/simple"

// 	"github.com/stretchr/testify/require"

// 	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
// 	"github.com/bronlabs/bron-crypto/pkg/base/curves"
// 	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
// 	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
// 	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
// 	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
// 	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
// 	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
// )

// func Test_HappyPathSchnorr(t *testing.T) {
// 	t.Parallel()

// 	t.Run("k256", func(t *testing.T) {
// 		t.Parallel()
// 		curve := k256.NewCurve()
// 		testHappyPathSchnorr(t, curve)
// 	})
// 	t.Run("p256", func(t *testing.T) {
// 		t.Parallel()
// 		curve := p256.NewCurve()
// 		testHappyPathSchnorr(t, curve)
// 	})
// 	t.Run("edwards25519", func(t *testing.T) {
// 		t.Parallel()
// 		curve := edwards25519.NewPrimeSubGroup()
// 		testHappyPathSchnorr(t, curve)
// 	})
// 	// t.Run("pallas", func(t *testing.T) {
// 	// 	t.Parallel()
// 	// 	curve := pasta.NewPallasCurve()
// 	// 	testHappyPathSchnorr(t, curve)
// 	// })
// 	// t.Run("vesta", func(t *testing.T) {
// 	// 	t.Parallel()
// 	// 	curve := pasta.NewVestaCurve()
// 	// 	testHappyPathSchnorr(t, curve)
// 	// })
// 	t.Run("bls12381g1", func(t *testing.T) {
// 		t.Parallel()
// 		curve := bls12381.NewG1Curve()
// 		testHappyPathSchnorr(t, curve)
// 	})
// 	t.Run("bls12381g2", func(t *testing.T) {
// 		t.Parallel()
// 		curve := bls12381.NewG2Curve()
// 		testHappyPathSchnorr(t, curve)
// 	})
// }

// //func Test_HappyPathBatchSchnorr(t *testing.T) {
// //	t.Parallel()
// //
// //	for i, c := range supportedCurve {
// //		i := i
// //		curve := c
// //		t.Run(curve.Name(), func(t *testing.T) {
// //			t.Parallel()
// //
// //			n := 64
// //			witness := make([]curves.Scalar, n)
// //			statement := make([]curves.Point, n)
// //			for j := 0; j < 64; j++ {
// //				var err error
// //				witness[j], err = curve.ScalarField().Random(crand.Reader)
// //				require.NoError(t, err)
// //				statement[j] = curve.ScalarBaseMult(witness[j])
// //			}
// //
// //			prng := crand.Reader
// //			protocol, err := batch_schnorr.NewSigmaProtocol(uint(n), curve.Generator(), prng)
// //			require.NoError(t, err)
// //			sessionID := []byte("some_session_id_for_test" + strconv.Itoa(i))
// //			transcript := hagrid.NewTranscript("Test"+strconv.Itoa(i), nil)
// //			proverTranscript := transcript.Clone()
// //			verifierTranscript := transcript.Clone()
// //
// //			prover, err := sigma.NewProver(sessionID, proverTranscript, protocol, statement, witness)
// //			require.NoError(t, err)
// //			verifier, err := sigma.NewVerifier(sessionID, verifierTranscript, protocol, statement, prng)
// //			require.NoError(t, err)
// //
// //			// round 1
// //			commitment, err := prover.Round1()
// //			require.NoError(t, err)
// //
// //			// round 2
// //			challenge, err := verifier.Round2(commitment)
// //			require.NoError(t, err)
// //
// //			// round 3
// //			response, err := prover.Round3(challenge)
// //			require.NoError(t, err)
// //
// //			// verify
// //			accepted := verifier.Verify(response)
// //			require.NoError(t, accepted)
// //
// //			proverBytes, err := proverTranscript.ExtractBytes("test"+strconv.Itoa(i), 32)
// //			require.NoError(t, err)
// //			verifierBytes, err := verifierTranscript.ExtractBytes("test"+strconv.Itoa(i), 32)
// //			require.NoError(t, err)
// //			require.True(t, bytes.Equal(proverBytes, verifierBytes))
// //		})
// //	}
// //}

// func testHappyPathSchnorr[P curves.Point[P, F, S], F algebra.FiniteFieldElement[F], S algebra.PrimeFieldElement[S]](t *testing.T, curve curves.Curve[P, F, S]) {
// 	t.Helper()
// 	prng := crand.Reader

// 	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
// 	require.True(t, ok)
// 	w, err := sf.Random(prng)
// 	require.NoError(t, err)
// 	witness := schnorr.NewWitness(w)
// 	statement := schnorr.NewStatement(curve.Generator().ScalarMul(w))

// 	protocol, err := schnorr.NewSigmaProtocol(curve.Generator(), prng)
// 	require.NoError(t, err)
// 	sessionID := []byte("some_session_id_for_test" + curve.Name())
// 	transcript := simple.NewTranscript("Test" + curve.Name())
// 	proverTranscript := transcript.Clone()
// 	verifierTranscript := transcript.Clone()

// 	prover, err := sigma.NewProver(sessionID, proverTranscript, protocol, statement, witness)
// 	require.NoError(t, err)
// 	verifier, err := sigma.NewVerifier(sessionID, verifierTranscript, protocol, statement, prng)
// 	require.NoError(t, err)

// 	// round 1
// 	commitment, err := prover.Round1()
// 	require.NoError(t, err)

// 	// round 2
// 	challenge, err := verifier.Round2(commitment)
// 	require.NoError(t, err)

// 	// round 3
// 	response, err := prover.Round3(challenge)
// 	require.NoError(t, err)

// 	// verify
// 	accepted := verifier.Verify(response)
// 	require.NoError(t, accepted)

// 	proverBytes, err := proverTranscript.ExtractBytes("test"+curve.Name(), 32)
// 	require.NoError(t, err)
// 	verifierBytes, err := verifierTranscript.ExtractBytes("test"+curve.Name(), 32)
// 	require.NoError(t, err)
// 	require.True(t, bytes.Equal(proverBytes, verifierBytes))
// }
