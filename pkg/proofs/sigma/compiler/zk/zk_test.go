package zk_test

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
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/zk"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

func TestZKCompiler_HappyPath(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testZKHappyPath(t, curve)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testZKHappyPath(t, curve)
	})
	t.Run("pallas", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewPallasCurve()
		testZKHappyPath(t, curve)
	})
	t.Run("vesta", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewVestaCurve()
		testZKHappyPath(t, curve)
	})
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		curve := edwards25519.NewPrimeSubGroup()
		testZKHappyPath(t, curve)
	})
	t.Run("BLS12381G1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		testZKHappyPath(t, curve)
	})
	t.Run("BLS12381G2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2()
		testZKHappyPath(t, curve)
	})
}

func testZKHappyPath[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](tb testing.TB, curve curves.Curve[P, B, S]) {
	tb.Helper()

	prng := crand.Reader
	var sessionId network.SID
	_, err := io.ReadFull(prng, sessionId[:])
	require.NoError(tb, err)

	schnorrProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(tb, err)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(tb, err)
	witness := &schnorr.Witness[S]{
		W: witnessValue,
	}

	statementValue := curve.ScalarBaseMul(witnessValue)
	statement := &schnorr.Statement[P, S]{
		X: statementValue,
	}

	proverTranscript := hagrid.NewTranscript("test")
	verifierTranscript := hagrid.NewTranscript("test")

	prover, err := zk.NewProver(sessionId, proverTranscript, schnorrProtocol, statement, witness)
	require.NoError(tb, err)
	require.NotNil(tb, prover)

	verifier, err := zk.NewVerifier(sessionId, verifierTranscript, schnorrProtocol, statement, prng)
	require.NoError(tb, err)
	require.NotNil(tb, verifier)

	// Round 1: Verifier commits to challenge
	challengeCommitment, err := verifier.Round1()
	require.NoError(tb, err)

	// Round 2: Prover receives challenge commitment, sends commitment
	proverCommitment, err := prover.Round2(challengeCommitment)
	require.NoError(tb, err)

	// Round 3: Verifier opens challenge commitment
	challenge, commWitness, err := verifier.Round3(proverCommitment)
	require.NoError(tb, err)

	// Round 4: Prover verifies commitment opening and computes response
	response, err := prover.Round4(challenge, commWitness)
	require.NoError(tb, err)

	// Round 5: Verifier verifies the response
	err = verifier.Verify(response)
	require.NoError(tb, err)

	// Verify transcripts match
	proverBytes, err := proverTranscript.ExtractBytes("test", 32)
	require.NoError(tb, err)
	verifierBytes, err := verifierTranscript.ExtractBytes("test", 32)
	require.NoError(tb, err)
	require.True(tb, bytes.Equal(proverBytes, verifierBytes))
}

func TestZKCompiler_WrongWitness(t *testing.T) {
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

	proverTranscript := hagrid.NewTranscript("test")
	verifierTranscript := hagrid.NewTranscript("test")

	prover, err := zk.NewProver(sessionId, proverTranscript, schnorrProtocol, statement, wrongWitness)
	require.NoError(t, err)

	verifier, err := zk.NewVerifier(sessionId, verifierTranscript, schnorrProtocol, statement, prng)
	require.NoError(t, err)

	// Run protocol with wrong witness
	challengeCommitment, err := verifier.Round1()
	require.NoError(t, err)

	proverCommitment, err := prover.Round2(challengeCommitment)
	require.NoError(t, err)

	challenge, commWitness, err := verifier.Round3(proverCommitment)
	require.NoError(t, err)

	response, err := prover.Round4(challenge, commWitness)
	require.NoError(t, err)

	// Verification should fail with wrong witness
	err = verifier.Verify(response)
	require.Error(t, err)
}

func TestZKCompiler_RoundOrderEnforcement(t *testing.T) {
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

	t.Run("prover cannot skip to round 4", func(t *testing.T) {
		t.Parallel()
		proverTranscript := hagrid.NewTranscript("test")
		prover, err := zk.NewProver(sessionId, proverTranscript, schnorrProtocol, statement, witness)
		require.NoError(t, err)

		// Try to call Round4 before Round2 - should fail due to wrong round
		var emptyWitness [32]byte
		_, err = prover.Round4(nil, emptyWitness)
		require.Error(t, err)
	})

	t.Run("verifier cannot skip to round 3", func(t *testing.T) {
		t.Parallel()
		verifierTranscript := hagrid.NewTranscript("test")
		verifier, err := zk.NewVerifier(sessionId, verifierTranscript, schnorrProtocol, statement, prng)
		require.NoError(t, err)

		// Try to call Round3 before Round1
		_, _, err = verifier.Round3(nil)
		require.Error(t, err)
	})

	t.Run("verifier cannot verify before round 5", func(t *testing.T) {
		t.Parallel()
		verifierTranscript := hagrid.NewTranscript("test")
		verifier, err := zk.NewVerifier(sessionId, verifierTranscript, schnorrProtocol, statement, prng)
		require.NoError(t, err)

		// Try to call Verify before completing rounds
		err = verifier.Verify(nil)
		require.Error(t, err)
	})
}

func TestZKCompiler_NilInputs(t *testing.T) {
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

	t.Run("prover with nil transcript", func(t *testing.T) {
		t.Parallel()
		_, err := zk.NewProver(sessionId, nil, schnorrProtocol, statement, witness)
		require.Error(t, err)
	})

	t.Run("prover with empty sessionId", func(t *testing.T) {
		t.Parallel()
		transcript := hagrid.NewTranscript("test")
		var emptySessionId network.SID
		_, err := zk.NewProver(emptySessionId, transcript, schnorrProtocol, statement, witness)
		require.Error(t, err)
	})

	t.Run("verifier with nil transcript", func(t *testing.T) {
		t.Parallel()
		_, err := zk.NewVerifier(sessionId, nil, schnorrProtocol, statement, prng)
		require.Error(t, err)
	})

	t.Run("verifier with empty sessionId", func(t *testing.T) {
		t.Parallel()
		transcript := hagrid.NewTranscript("test")
		var emptySessionId network.SID
		_, err := zk.NewVerifier(emptySessionId, transcript, schnorrProtocol, statement, prng)
		require.Error(t, err)
	})
}

func TestZKCompiler_MultipleIterations(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := crand.Reader

	for range 10 {
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

		proverTranscript := hagrid.NewTranscript("test")
		verifierTranscript := hagrid.NewTranscript("test")

		prover, err := zk.NewProver(sessionId, proverTranscript, schnorrProtocol, statement, witness)
		require.NoError(t, err)

		verifier, err := zk.NewVerifier(sessionId, verifierTranscript, schnorrProtocol, statement, prng)
		require.NoError(t, err)

		challengeCommitment, err := verifier.Round1()
		require.NoError(t, err)

		proverCommitment, err := prover.Round2(challengeCommitment)
		require.NoError(t, err)

		challenge, commWitness, err := verifier.Round3(proverCommitment)
		require.NoError(t, err)

		response, err := prover.Round4(challenge, commWitness)
		require.NoError(t, err)

		err = verifier.Verify(response)
		require.NoError(t, err)
	}
}
