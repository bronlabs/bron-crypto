package zk_test

import (
	"bytes"
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
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/zk"
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

	prng := pcg.NewRandomised()

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

	const proverId = 1
	const verifierId = 2
	quorum := hashset.NewComparable[sharing.ID](proverId, verifierId).Freeze()
	ctxs := session_testutils.MakeRandomContexts(tb, quorum, prng)

	prover, err := zk.NewProver(ctxs[proverId], schnorrProtocol, statement, witness)
	require.NoError(tb, err)
	require.NotNil(tb, prover)

	verifier, err := zk.NewVerifier(ctxs[verifierId], schnorrProtocol, statement, prng)
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
	proverBytes, err := ctxs[proverId].Transcript().ExtractBytes("test", 32)
	require.NoError(tb, err)
	verifierBytes, err := ctxs[verifierId].Transcript().ExtractBytes("test", 32)
	require.NoError(tb, err)
	require.True(tb, bytes.Equal(proverBytes, verifierBytes))
}

func TestZKCompiler_WrongWitness(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()

	var sessionID network.SID
	_, err := io.ReadFull(prng, sessionID[:])
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

	const proverId = 1
	const verifierId = 2
	quorum := hashset.NewComparable[sharing.ID](proverId, verifierId).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	prover, err := zk.NewProver(ctxs[proverId], schnorrProtocol, statement, wrongWitness)
	require.NoError(t, err)

	verifier, err := zk.NewVerifier(ctxs[verifierId], schnorrProtocol, statement, prng)
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

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()

	schnorrProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	witness := schnorr.NewWitness(witnessValue)
	statementValue := curve.ScalarBaseMul(witnessValue)
	statement := schnorr.NewStatement(statementValue)

	const proverId = 1
	const verifierId = 2
	quorum := hashset.NewComparable[sharing.ID](proverId, verifierId).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	t.Run("prover cannot skip to round 4", func(t *testing.T) {
		t.Parallel()
		prover, err := zk.NewProver(ctxs[proverId], schnorrProtocol, statement, witness)
		require.NoError(t, err)

		// Try to call Round4 before Round2 - should fail due to wrong round
		var emptyWitness [32]byte
		_, err = prover.Round4(nil, emptyWitness)
		require.Error(t, err)
	})

	t.Run("verifier cannot skip to round 3", func(t *testing.T) {
		t.Parallel()
		verifier, err := zk.NewVerifier(ctxs[verifierId], schnorrProtocol, statement, prng)
		require.NoError(t, err)

		// Try to call Round3 before Round1
		_, _, err = verifier.Round3(nil)
		require.Error(t, err)
	})

	t.Run("verifier cannot verify before round 5", func(t *testing.T) {
		t.Parallel()
		verifier, err := zk.NewVerifier(ctxs[verifierId], schnorrProtocol, statement, prng)
		require.NoError(t, err)

		// Try to call Verify before completing rounds
		err = verifier.Verify(nil)
		require.Error(t, err)
	})
}

func TestZKCompiler_NilInputs(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()

	var sessionID network.SID
	_, err := io.ReadFull(prng, sessionID[:])
	require.NoError(t, err)

	schnorrProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	witnessValue, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	witness := schnorr.NewWitness(witnessValue)
	statementValue := curve.ScalarBaseMul(witnessValue)
	statement := schnorr.NewStatement(statementValue)

	t.Run("prover with nil ctx", func(t *testing.T) {
		t.Parallel()
		_, err := zk.NewProver(nil, schnorrProtocol, statement, witness)
		require.Error(t, err)
	})

	t.Run("verifier with nil transcript", func(t *testing.T) {
		t.Parallel()
		_, err := zk.NewVerifier(nil, schnorrProtocol, statement, prng)
		require.Error(t, err)
	})
}

func TestZKCompiler_MultipleIterations(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()

	for range 10 {
		schnorrProtocol, err := schnorr.NewProtocol(curve.Generator(), prng)
		require.NoError(t, err)

		witnessValue, err := curve.ScalarField().Random(prng)
		require.NoError(t, err)
		witness := schnorr.NewWitness(witnessValue)
		statementValue := curve.ScalarBaseMul(witnessValue)
		statement := schnorr.NewStatement(statementValue)

		const proverId = 1
		const verifierId = 2
		quorum := hashset.NewComparable[sharing.ID](proverId, verifierId).Freeze()
		ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

		prover, err := zk.NewProver(ctxs[proverId], schnorrProtocol, statement, witness)
		require.NoError(t, err)

		verifier, err := zk.NewVerifier(ctxs[verifierId], schnorrProtocol, statement, prng)
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
