package randfischlin_test

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
	"github.com/stretchr/testify/require"
)

func Test_HappyPathSchnorr(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testSchnorrHappyPath(t, curve)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testSchnorrHappyPath(t, curve)
	})
	t.Run("pallas", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewPallasCurve()
		testSchnorrHappyPath(t, curve)
	})
	t.Run("vesta", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewVestaCurve()
		testSchnorrHappyPath(t, curve)
	})
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		curve := edwards25519.NewPrimeSubGroup()
		testSchnorrHappyPath(t, curve)
	})
	t.Run("BLS12381G1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		testSchnorrHappyPath(t, curve)
	})
	t.Run("BLS12381G2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2()
		testSchnorrHappyPath(t, curve)
	})
}

func testSchnorrHappyPath[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](tb testing.TB, curve curves.Curve[P, B, S]) {
	tb.Helper()

	prng := crand.Reader
	var sessionId network.SID
	_, err := io.ReadFull(prng, sessionId[:])
	require.NoError(tb, err)

	schnorrProtocol, err := schnorr.NewProtocol(
		curve.Generator(), prng)
	require.NoError(tb, err)

	nizk, err := randfischlin.NewCompiler(schnorrProtocol, prng)
	require.NoError(tb, err)

	println("nizk", nizk)

	proverTranscript := hagrid.NewTranscript("test")
	prover, err := nizk.NewProver(sessionId, proverTranscript)
	require.NoError(tb, err)
	require.NotNil(tb, prover)

	verifierTranscript := hagrid.NewTranscript("test")
	verifier, err := nizk.NewVerifier(sessionId, verifierTranscript)
	require.NoError(tb, err)
	require.NotNil(tb, verifier)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(tb, err)
	witness := &schnorr.Witness[S]{
		W: witnessValue,
	}

	statementValue := curve.ScalarBaseMul(witnessValue)
	statement := &schnorr.Statement[P, S]{
		X: statementValue,
	}

	proof, err := prover.Prove(statement, witness)
	require.NoError(tb, err)

	err = verifier.Verify(statement, proof)
	require.NoError(tb, err)

	proverBytes, err := proverTranscript.ExtractBytes("test", 32)
	require.NoError(tb, err)
	verifierBytes, err := verifierTranscript.ExtractBytes("test", 32)
	require.NoError(tb, err)

	require.True(tb, bytes.Equal(proverBytes, verifierBytes))
}
