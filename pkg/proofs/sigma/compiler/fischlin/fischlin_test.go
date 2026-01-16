package fischlin_test

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fischlin"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
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

	schnorrProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(tb, err)

	nizk, err := fischlin.NewCompiler(schnorrProtocol, prng)
	require.NoError(tb, err)

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

func TestFischlin_WrongWitness(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	curve := k256.NewCurve()

	var sessionId network.SID
	_, err := io.ReadFull(prng, sessionId[:])
	require.NoError(t, err)

	schnorrProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	// Create correct witness and statement
	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	statementValue := curve.ScalarBaseMul(witnessValue)
	statement := schnorr.NewStatement(statementValue)

	// Create wrong witness
	wrongWitnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	wrongWitness := schnorr.NewWitness(wrongWitnessValue)

	nizk, err := fischlin.NewCompiler(schnorrProtocol, prng)
	require.NoError(t, err)

	proverTranscript := hagrid.NewTranscript("test")
	verifierTranscript := proverTranscript.Clone()

	prover, err := nizk.NewProver(sessionId, proverTranscript)
	require.NoError(t, err)
	proof, err := prover.Prove(statement, wrongWitness)
	require.NoError(t, err)

	verifier, err := nizk.NewVerifier(sessionId, verifierTranscript)
	require.NoError(t, err)

	// Verification should fail with wrong witness
	err = verifier.Verify(statement, proof)
	require.Error(t, err)
}

func TestFischlin_TamperedProof(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	curve := k256.NewCurve()

	var sessionId network.SID
	_, err := io.ReadFull(prng, sessionId[:])
	require.NoError(t, err)

	schnorrProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	witness := schnorr.NewWitness(witnessValue)
	statementValue := curve.ScalarBaseMul(witnessValue)
	statement := schnorr.NewStatement(statementValue)

	nizk, err := fischlin.NewCompiler(schnorrProtocol, prng)
	require.NoError(t, err)

	proverTranscript := hagrid.NewTranscript("test")
	verifierTranscript := proverTranscript.Clone()

	prover, err := nizk.NewProver(sessionId, proverTranscript)
	require.NoError(t, err)
	proof, err := prover.Prove(statement, witness)
	require.NoError(t, err)

	// Tamper with the proof
	if len(proof) > 0 {
		proof[0] ^= 0xFF
	}

	verifier, err := nizk.NewVerifier(sessionId, verifierTranscript)
	require.NoError(t, err)

	// Verification should fail with tampered proof
	err = verifier.Verify(statement, proof)
	require.Error(t, err)
}

func TestFischlin_EmptyProof(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	curve := k256.NewCurve()

	var sessionId network.SID
	_, err := io.ReadFull(prng, sessionId[:])
	require.NoError(t, err)

	schnorrProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	statementValue := curve.ScalarBaseMul(witnessValue)
	statement := schnorr.NewStatement(statementValue)

	nizk, err := fischlin.NewCompiler(schnorrProtocol, prng)
	require.NoError(t, err)

	verifierTranscript := hagrid.NewTranscript("test")
	verifier, err := nizk.NewVerifier(sessionId, verifierTranscript)
	require.NoError(t, err)

	// Verification should fail with empty proof
	err = verifier.Verify(statement, nil)
	require.Error(t, err)

	err = verifier.Verify(statement, []byte{})
	require.Error(t, err)
}

func TestFischlin_WrongSessionId(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	curve := k256.NewCurve()

	var proverSessionId, verifierSessionId network.SID
	_, err := io.ReadFull(prng, proverSessionId[:])
	require.NoError(t, err)
	_, err = io.ReadFull(prng, verifierSessionId[:])
	require.NoError(t, err)

	schnorrProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	witness := schnorr.NewWitness(witnessValue)
	statementValue := curve.ScalarBaseMul(witnessValue)
	statement := schnorr.NewStatement(statementValue)

	nizk, err := fischlin.NewCompiler(schnorrProtocol, prng)
	require.NoError(t, err)

	proverTranscript := hagrid.NewTranscript("test")
	verifierTranscript := hagrid.NewTranscript("test")

	prover, err := nizk.NewProver(proverSessionId, proverTranscript)
	require.NoError(t, err)
	proof, err := prover.Prove(statement, witness)
	require.NoError(t, err)

	// Use different session ID for verifier
	verifier, err := nizk.NewVerifier(verifierSessionId, verifierTranscript)
	require.NoError(t, err)

	// Verification should fail with wrong session ID
	err = verifier.Verify(statement, proof)
	require.Error(t, err)
}

func TestFischlin_NilCompilerInput(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	curve := k256.NewCurve()

	schnorrProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	// nil protocol
	_, err = fischlin.NewCompiler[
		*schnorr.Statement[*k256.Point, *k256.Scalar],
		*schnorr.Witness[*k256.Scalar],
		*schnorr.Commitment[*k256.Point, *k256.Scalar],
		*schnorr.State[*k256.Scalar],
		*schnorr.Response[*k256.Scalar],
	](nil, prng)
	require.Error(t, err)

	// nil prng
	_, err = fischlin.NewCompiler(schnorrProtocol, nil)
	require.Error(t, err)
}

func TestFischlin_TranscriptsMatch(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		testFischlinTranscriptsMatch(t, k256.NewCurve())
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		testFischlinTranscriptsMatch(t, p256.NewCurve())
	})
}

func testFischlinTranscriptsMatch[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](tb testing.TB, curve curves.Curve[P, B, S]) {
	tb.Helper()

	prng := crand.Reader
	var sessionId network.SID
	_, err := io.ReadFull(prng, sessionId[:])
	require.NoError(tb, err)

	schnorrProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(tb, err)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(tb, err)
	witness := &schnorr.Witness[S]{W: witnessValue}
	statementValue := curve.ScalarBaseMul(witnessValue)
	statement := &schnorr.Statement[P, S]{X: statementValue}

	nizk, err := fischlin.NewCompiler(schnorrProtocol, prng)
	require.NoError(tb, err)

	proverTranscript := hagrid.NewTranscript("test")
	verifierTranscript := hagrid.NewTranscript("test")

	prover, err := nizk.NewProver(sessionId, proverTranscript)
	require.NoError(tb, err)
	proof, err := prover.Prove(statement, witness)
	require.NoError(tb, err)

	verifier, err := nizk.NewVerifier(sessionId, verifierTranscript)
	require.NoError(tb, err)
	err = verifier.Verify(statement, proof)
	require.NoError(tb, err)

	// Verify transcripts match after proof/verify
	proverBytes, err := proverTranscript.ExtractBytes("final", 32)
	require.NoError(tb, err)
	verifierBytes, err := verifierTranscript.ExtractBytes("final", 32)
	require.NoError(tb, err)
	require.True(tb, bytes.Equal(proverBytes, verifierBytes))
}
