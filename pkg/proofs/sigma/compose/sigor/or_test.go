package sigor_test

import (
	crand "crypto/rand"
	"crypto/subtle"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compose/sigor"
)

func Test_Or_HappyPath(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testOrHappyPath(t, curve, 2)
		testOrHappyPath(t, curve, 3)
		testOrHappyPath(t, curve, 5)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testOrHappyPath(t, curve, 2)
		testOrHappyPath(t, curve, 3)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		testOrHappyPath(t, curve, 2)
		testOrHappyPath(t, curve, 3)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2()
		testOrHappyPath(t, curve, 2)
	})
}

func Test_Or_Simulator(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testOrSimulator(t, curve, 2)
		testOrSimulator(t, curve, 3)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testOrSimulator(t, curve, 2)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		testOrSimulator(t, curve, 2)
	})
}

func Test_Or_XORConstraint(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testOrXORConstraint(t, curve, 2)
		testOrXORConstraint(t, curve, 3)
		testOrXORConstraint(t, curve, 5)
	})
}

func Test_Or_InvalidInputs(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	base, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	protocol, err := schnorr.NewProtocol(base, crand.Reader)
	require.NoError(t, err)

	t.Run("nil_protocol", func(t *testing.T) {
		_, err := sigor.Compose[*schnorr.Statement[*k256.Point, *k256.Scalar], *schnorr.Witness[*k256.Scalar], *schnorr.Commitment[*k256.Point, *k256.Scalar], *schnorr.State[*k256.Scalar], *schnorr.Response[*k256.Scalar]](nil, 2, crand.Reader)
		require.Error(t, err)
	})

	t.Run("count_less_than_2", func(t *testing.T) {
		_, err := sigor.Compose(protocol, 1, crand.Reader)
		require.Error(t, err)

		_, err = sigor.Compose(protocol, 0, crand.Reader)
		require.Error(t, err)
	})

	t.Run("nil_prng", func(t *testing.T) {
		_, err := sigor.Compose(protocol, 2, nil)
		require.Error(t, err)
	})
}

func testOrHappyPath[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S], count uint,
) {
	tb.Helper()

	prng := crand.Reader
	base, err := curve.Random(crand.Reader)
	require.NoError(tb, err)

	protocol, err := schnorr.NewProtocol(base, prng)
	require.NoError(tb, err)

	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	require.True(tb, ok)

	// Create statements and witness
	// Only index 0 has a valid witness
	statements := make(sigor.Statement[*schnorr.Statement[P, S]], count)
	var witness sigor.Witness[*schnorr.Witness[S]]

	for i := range count {
		if i == 0 {
			// Valid witness: x = g^w
			w, err := sf.Random(crand.Reader)
			require.NoError(tb, err)
			x := base.ScalarMul(w)
			statements[i] = schnorr.NewStatement(x)
			witness = sigor.NewWitness(schnorr.NewWitness(w))
		} else {
			// Invalid statement: random x with no known witness
			x, err := curve.Random(crand.Reader)
			require.NoError(tb, err)
			statements[i] = schnorr.NewStatement(x)
		}
	}

	// Compose OR protocol
	orProtocol, err := sigor.Compose(protocol, count, prng)
	require.NoError(tb, err)

	// Validate that exactly one statement is valid
	err = orProtocol.ValidateStatement(statements, witness)
	require.NoError(tb, err)

	// Round 1: Prover commitment
	commitment, state, err := orProtocol.ComputeProverCommitment(statements, witness)
	require.NoError(tb, err)

	// Round 2: Verifier challenge
	challenge := make([]byte, orProtocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(tb, err)

	// Round 3: Prover response
	response, err := orProtocol.ComputeProverResponse(statements, witness, commitment, state, challenge)
	require.NoError(tb, err)

	// Verify
	err = orProtocol.Verify(statements, commitment, challenge, response)
	require.NoError(tb, err)
}

func testOrSimulator[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S], count uint,
) {
	tb.Helper()

	prng := crand.Reader
	base, err := curve.Random(crand.Reader)
	require.NoError(tb, err)

	protocol, err := schnorr.NewProtocol(base, prng)
	require.NoError(tb, err)

	// Create random statements (no valid witnesses)
	statements := make(sigor.Statement[*schnorr.Statement[P, S]], count)
	for i := range count {
		x, err := curve.Random(crand.Reader)
		require.NoError(tb, err)
		statements[i] = schnorr.NewStatement(x)
	}

	// Compose OR protocol
	orProtocol, err := sigor.Compose(protocol, count, prng)
	require.NoError(tb, err)

	// Generate random challenge
	challenge := make([]byte, orProtocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(tb, err)

	// Run simulator
	commitment, response, err := orProtocol.RunSimulator(statements, challenge)
	require.NoError(tb, err)

	// Verify simulated proof
	err = orProtocol.Verify(statements, commitment, challenge, response)
	require.NoError(tb, err)
}

func testOrXORConstraint[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S], count uint,
) {
	tb.Helper()

	prng := crand.Reader
	base, err := curve.Random(crand.Reader)
	require.NoError(tb, err)

	protocol, err := schnorr.NewProtocol(base, prng)
	require.NoError(tb, err)

	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	require.True(tb, ok)

	// Create statements with one valid witness
	statements := make(sigor.Statement[*schnorr.Statement[P, S]], count)
	var witness sigor.Witness[*schnorr.Witness[S]]

	for i := range count {
		if i == 0 {
			w, err := sf.Random(crand.Reader)
			require.NoError(tb, err)
			x := base.ScalarMul(w)
			statements[i] = schnorr.NewStatement(x)
			witness = sigor.NewWitness(schnorr.NewWitness(w))
		} else {
			x, err := curve.Random(crand.Reader)
			require.NoError(tb, err)
			statements[i] = schnorr.NewStatement(x)
		}
	}

	// Compose OR protocol
	orProtocol, err := sigor.Compose(protocol, count, prng)
	require.NoError(tb, err)

	// Run protocol
	commitment, state, err := orProtocol.ComputeProverCommitment(statements, witness)
	require.NoError(tb, err)

	challenge := make([]byte, orProtocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(tb, err)

	response, err := orProtocol.ComputeProverResponse(statements, witness, commitment, state, challenge)
	require.NoError(tb, err)

	// Verify XOR constraint: e_0 XOR e_1 XOR ... XOR e_n = challenge
	xored := make([]byte, len(challenge))
	copy(xored, response.E[0])
	for i := 1; i < len(response.E); i++ {
		subtle.XORBytes(xored, xored, response.E[i])
	}
	require.Equal(tb, challenge, xored, "XOR constraint should hold")
}
