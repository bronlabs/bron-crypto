package okamoto_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/proofs/okamoto"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		testHappyPath(t, k256.NewCurve(), 2)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		testHappyPath(t, p256.NewCurve(), 2)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		testHappyPath(t, bls12381.NewG1(), 2)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		testHappyPath(t, bls12381.NewG2(), 2)
	})
}

func Test_MultipleGenerators(t *testing.T) {
	t.Parallel()

	t.Run("3_generators", func(t *testing.T) {
		t.Parallel()
		testHappyPath(t, k256.NewCurve(), 3)
	})
	t.Run("5_generators", func(t *testing.T) {
		t.Parallel()
		testHappyPath(t, k256.NewCurve(), 5)
	})
}

func Test_Simulator(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		testSimulator(t, k256.NewCurve(), 2)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		testSimulator(t, p256.NewCurve(), 2)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		testSimulator(t, bls12381.NewG1(), 2)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		testSimulator(t, bls12381.NewG2(), 2)
	})
}

func Test_Extractor(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		testExtractor(t, k256.NewCurve(), 2)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		testExtractor(t, p256.NewCurve(), 2)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		testExtractor(t, bls12381.NewG1(), 2)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		testExtractor(t, bls12381.NewG2(), 2)
	})
}

func Test_PedersenCommitmentOpening(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		testPedersenOpening(t, k256.NewCurve())
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		testPedersenOpening(t, p256.NewCurve())
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		testPedersenOpening(t, bls12381.NewG1())
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		testPedersenOpening(t, bls12381.NewG2())
	})
}

func Test_VerificationFailsWithWrongWitness(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()

	g1, err := curve.Random(pcg.NewRandomised())
	require.NoError(t, err)
	g2, err := curve.Random(pcg.NewRandomised())
	require.NoError(t, err)

	protocol, err := okamoto.NewProtocol([]*k256.Point{g1, g2}, prng)
	require.NoError(t, err)

	sf := k256.NewScalarField()
	w1, err := sf.Random(pcg.NewRandomised())
	require.NoError(t, err)
	w2, err := sf.Random(pcg.NewRandomised())
	require.NoError(t, err)

	statement, err := okamoto.NewStatement(g1.ScalarMul(w1), g2.ScalarMul(w2))
	require.NoError(t, err)

	// Create wrong witness
	wrongW1, err := sf.Random(pcg.NewRandomised())
	require.NoError(t, err)
	wrongW2, err := sf.Random(pcg.NewRandomised())
	require.NoError(t, err)
	wrongWitness, err := okamoto.NewWitness(wrongW1, wrongW2)
	require.NoError(t, err)

	// Run protocol with wrong witness
	commitment, state, err := protocol.ComputeProverCommitment(statement, wrongWitness)
	require.NoError(t, err)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(pcg.NewRandomised(), challenge)
	require.NoError(t, err)

	response, err := protocol.ComputeProverResponse(statement, wrongWitness, commitment, state, challenge)
	require.NoError(t, err)

	err = protocol.Verify(statement, commitment, challenge, response)
	require.Error(t, err)
}

func Test_ValidateStatement(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	sf := k256.NewScalarField()

	g1, err := curve.Random(pcg.NewRandomised())
	require.NoError(t, err)
	g2, err := curve.Random(pcg.NewRandomised())
	require.NoError(t, err)

	protocol, err := okamoto.NewProtocol([]*k256.Point{g1, g2}, pcg.NewRandomised())
	require.NoError(t, err)

	w1, err := sf.Random(pcg.NewRandomised())
	require.NoError(t, err)
	w2, err := sf.Random(pcg.NewRandomised())
	require.NoError(t, err)

	witness, err := okamoto.NewWitness(w1, w2)
	require.NoError(t, err)
	statement, err := okamoto.NewStatement(g1.ScalarMul(w1), g2.ScalarMul(w2))
	require.NoError(t, err)

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		err := protocol.ValidateStatement(statement, witness)
		require.NoError(t, err)
	})

	t.Run("invalid", func(t *testing.T) {
		t.Parallel()
		wrongW1, err := sf.Random(pcg.NewRandomised())
		require.NoError(t, err)
		wrongW2, err := sf.Random(pcg.NewRandomised())
		require.NoError(t, err)
		wrongWitness, err := okamoto.NewWitness(wrongW1, wrongW2)
		require.NoError(t, err)

		err = protocol.ValidateStatement(statement, wrongWitness)
		require.Error(t, err)
	})
}

func Test_NewProtocolErrors(t *testing.T) {
	t.Parallel()

	t.Run("no generators", func(t *testing.T) {
		t.Parallel()
		_, err := okamoto.NewProtocol([]*k256.Point{}, pcg.NewRandomised())
		require.Error(t, err)
	})

	t.Run("nil prng", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		g, err := curve.Random(pcg.NewRandomised())
		require.NoError(t, err)
		_, err = okamoto.NewProtocol([]*k256.Point{g}, nil)
		require.Error(t, err)
	})
}

func Test_NewWitnessErrors(t *testing.T) {
	t.Parallel()

	t.Run("no values", func(t *testing.T) {
		t.Parallel()
		_, err := okamoto.NewWitness[*k256.Scalar]()
		require.Error(t, err)
	})
}

func Test_NewStatementErrors(t *testing.T) {
	t.Parallel()

	t.Run("no values", func(t *testing.T) {
		t.Parallel()
		_, err := okamoto.NewStatement[*k256.Point]()
		require.Error(t, err)
	})
}

// --- Generic test helpers ---

func testHappyPath[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S], m int,
) {
	tb.Helper()

	prng := pcg.NewRandomised()

	generators := make([]P, m)
	for i := range generators {
		g, err := curve.Random(pcg.NewRandomised())
		require.NoError(tb, err)
		generators[i] = g
	}

	protocol, err := okamoto.NewProtocol(generators, prng)
	require.NoError(tb, err)

	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	require.True(tb, ok)

	witnessScalars := make([]S, m)
	statementParts := make([]P, m)
	for i := range m {
		w, err := sf.Random(pcg.NewRandomised())
		require.NoError(tb, err)
		witnessScalars[i] = w
		statementParts[i] = generators[i].ScalarMul(w)
	}

	witness, err := okamoto.NewWitness(witnessScalars...)
	require.NoError(tb, err)
	statement, err := okamoto.NewStatement(statementParts...)
	require.NoError(tb, err)

	// round 1
	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(tb, err)

	// round 2
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(pcg.NewRandomised(), challenge)
	require.NoError(tb, err)

	// round 3
	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(tb, err)

	// verify
	err = protocol.Verify(statement, commitment, challenge, response)
	require.NoError(tb, err)
}

func testSimulator[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S], m int,
) {
	tb.Helper()

	generators := make([]P, m)
	for i := range generators {
		g, err := curve.Random(pcg.NewRandomised())
		require.NoError(tb, err)
		generators[i] = g
	}

	protocol, err := okamoto.NewProtocol(generators, pcg.NewRandomised())
	require.NoError(tb, err)

	// Random statement (simulator does not need a valid witness)
	x, err := curve.Random(pcg.NewRandomised())
	require.NoError(tb, err)
	statement, err := okamoto.NewStatement(x)
	require.NoError(tb, err)

	// simulate
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(pcg.NewRandomised(), challenge)
	require.NoError(tb, err)
	commitment, response, err := protocol.RunSimulator(statement, challenge)
	require.NoError(tb, err)

	// verify
	err = protocol.Verify(statement, commitment, challenge, response)
	require.NoError(tb, err)
}

func testExtractor[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S], m int,
) {
	tb.Helper()

	prng := pcg.NewRandomised()

	generators := make([]P, m)
	for i := range generators {
		g, err := curve.Random(pcg.NewRandomised())
		require.NoError(tb, err)
		generators[i] = g
	}

	protocol, err := okamoto.NewProtocol(generators, prng)
	require.NoError(tb, err)

	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	require.True(tb, ok)

	witnessScalars := make([]S, m)
	statementParts := make([]P, m)
	for i := range m {
		w, err := sf.Random(pcg.NewRandomised())
		require.NoError(tb, err)
		witnessScalars[i] = w
		statementParts[i] = generators[i].ScalarMul(w)
	}

	witness, err := okamoto.NewWitness(witnessScalars...)
	require.NoError(tb, err)
	statement, err := okamoto.NewStatement(statementParts...)
	require.NoError(tb, err)

	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(tb, err)

	challenge1 := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(pcg.NewRandomised(), challenge1)
	require.NoError(tb, err)
	challenge2 := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(pcg.NewRandomised(), challenge2)
	require.NoError(tb, err)

	response1, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge1)
	require.NoError(tb, err)
	response2, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge2)
	require.NoError(tb, err)

	// extract
	ei := []sigma.ChallengeBytes{challenge1, challenge2}
	zi := []*okamoto.Response[S]{response1, response2}

	wExtracted, err := protocol.Extract(statement, commitment, ei, zi)
	require.NoError(tb, err)
	require.True(tb, wExtracted.Value().Equal(witness.Value()))
}

func testPedersenOpening[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	t *testing.T, curve curves.Curve[P, F, S],
) {
	t.Helper()

	prng := pcg.NewRandomised()

	// Create two independent generators for the Pedersen commitment key.
	g, err := curve.Random(pcg.NewRandomised())
	require.NoError(t, err)
	h, err := curve.Random(pcg.NewRandomised())
	require.NoError(t, err)

	key, err := pedersen.NewCommitmentKey(g, h)
	require.NoError(t, err)
	scheme, err := pedersen.NewScheme(key)
	require.NoError(t, err)
	committer, err := scheme.Committer()
	require.NoError(t, err)

	// Commit to a random message.
	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	require.True(t, ok)
	msgScalar, err := sf.Random(pcg.NewRandomised())
	require.NoError(t, err)
	message := pedersen.NewMessage(msgScalar)

	commitment, pedersenWitness, err := committer.Commit(message, pcg.NewRandomised())
	require.NoError(t, err)

	// Prove knowledge of opening (m, r) such that C = g^m * h^r using Okamoto.
	generators := []P{key.G(), key.H()}
	protocol, err := okamoto.NewProtocol(generators, prng)
	require.NoError(t, err)

	// The Okamoto witness is the pair (message, randomness).
	okaWitness, err := okamoto.NewWitness(message.Value(), pedersenWitness.Value())
	require.NoError(t, err)

	t.Run("valid opening", func(t *testing.T) {
		t.Parallel()
		// The Okamoto statement is the commitment point itself.
		okaStatement, err := okamoto.NewStatement(commitment.Value())
		require.NoError(t, err)

		// Verify that phi(witness) == statement.
		err = protocol.ValidateStatement(okaStatement, okaWitness)
		require.NoError(t, err)

		// round 1
		com, state, err := protocol.ComputeProverCommitment(okaStatement, okaWitness)
		require.NoError(t, err)

		// round 2
		challenge := make([]byte, protocol.GetChallengeBytesLength())
		_, err = io.ReadFull(pcg.NewRandomised(), challenge)
		require.NoError(t, err)

		// round 3
		response, err := protocol.ComputeProverResponse(okaStatement, okaWitness, com, state, challenge)
		require.NoError(t, err)

		// verify
		err = protocol.Verify(okaStatement, com, challenge, response)
		require.NoError(t, err)
	})

	t.Run("invalid opening", func(t *testing.T) {
		t.Parallel()
		randomPoint, err := curve.Random(pcg.NewRandomised())
		require.NoError(t, err)
		// The Okamoto statement is the commitment point itself.
		invalidStatement, err := okamoto.NewStatement(randomPoint)
		require.NoError(t, err)

		// Verify that phi(witness) == statement.
		err = protocol.ValidateStatement(invalidStatement, okaWitness)
		require.Error(t, err)

		// round 1
		com, state, err := protocol.ComputeProverCommitment(invalidStatement, okaWitness)
		require.NoError(t, err)

		// round 2
		challenge := make([]byte, protocol.GetChallengeBytesLength())
		_, err = io.ReadFull(pcg.NewRandomised(), challenge)
		require.NoError(t, err)

		// round 3
		response, err := protocol.ComputeProverResponse(invalidStatement, okaWitness, com, state, challenge)
		require.NoError(t, err)

		// verify
		err = protocol.Verify(invalidStatement, com, challenge, response)
		require.Error(t, err)
	})
}
