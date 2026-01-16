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

func Test_CartesianOr_HappyPath_FirstBranch(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testCartesianOrHappyPath(t, curve, 0)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testCartesianOrHappyPath(t, curve, 0)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		testCartesianOrHappyPath(t, curve, 0)
	})
}

func Test_CartesianOr_HappyPath_SecondBranch(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testCartesianOrHappyPath(t, curve, 1)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testCartesianOrHappyPath(t, curve, 1)
	})
}

func Test_CartesianOr_Simulator(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testCartesianOrSimulator(t, curve)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testCartesianOrSimulator(t, curve)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		testCartesianOrSimulator(t, curve)
	})
}

func Test_CartesianOr_XORConstraint(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testCartesianOrXORConstraint(t, curve)
	})
}

func testCartesianOrHappyPath[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S], validBranch int,
) {
	tb.Helper()

	prng := crand.Reader
	base, err := curve.Random(crand.Reader)
	require.NoError(tb, err)

	protocol, err := schnorr.NewProtocol(base, prng)
	require.NoError(tb, err)

	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	require.True(tb, ok)

	// Create two witnesses - only one is valid
	w0, err := sf.Random(crand.Reader)
	require.NoError(tb, err)
	w1, err := sf.Random(crand.Reader)
	require.NoError(tb, err)

	var x0, x1 P
	if validBranch == 0 {
		x0 = base.ScalarMul(w0) // Valid
		x1, err = curve.Random(crand.Reader)
		require.NoError(tb, err) // Invalid
	} else {
		x0, err = curve.Random(crand.Reader)
		require.NoError(tb, err) // Invalid
		x1 = base.ScalarMul(w1)  // Valid
	}

	statement := sigor.CartesianComposeStatements(schnorr.NewStatement(x0), schnorr.NewStatement(x1))
	witness := sigor.CartesianComposeWitnesses(schnorr.NewWitness(w0), schnorr.NewWitness(w1))

	// Compose OR protocol
	orProtocol := sigor.CartesianCompose(protocol, protocol, prng)

	// Round 1: Prover commitment
	commitment, state, err := orProtocol.ComputeProverCommitment(statement, witness)
	require.NoError(tb, err)

	// Round 2: Verifier challenge
	challenge := make([]byte, orProtocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(tb, err)

	// Round 3: Prover response
	response, err := orProtocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(tb, err)

	// Verify
	err = orProtocol.Verify(statement, commitment, challenge, response)
	require.NoError(tb, err)
}

func testCartesianOrSimulator[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S],
) {
	tb.Helper()

	prng := crand.Reader
	base, err := curve.Random(crand.Reader)
	require.NoError(tb, err)

	protocol, err := schnorr.NewProtocol(base, prng)
	require.NoError(tb, err)

	// Create random statements (no valid witnesses)
	x0, err := curve.Random(crand.Reader)
	require.NoError(tb, err)
	x1, err := curve.Random(crand.Reader)
	require.NoError(tb, err)

	statement := sigor.CartesianComposeStatements(schnorr.NewStatement(x0), schnorr.NewStatement(x1))

	// Compose OR protocol
	orProtocol := sigor.CartesianCompose(protocol, protocol, prng)

	// Generate random challenge
	challenge := make([]byte, orProtocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(tb, err)

	// Run simulator
	commitment, response, err := orProtocol.RunSimulator(statement, challenge)
	require.NoError(tb, err)

	// Verify simulated proof
	err = orProtocol.Verify(statement, commitment, challenge, response)
	require.NoError(tb, err)
}

func testCartesianOrXORConstraint[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S],
) {
	tb.Helper()

	prng := crand.Reader
	base, err := curve.Random(crand.Reader)
	require.NoError(tb, err)

	protocol, err := schnorr.NewProtocol(base, prng)
	require.NoError(tb, err)

	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	require.True(tb, ok)

	// Create two witnesses - first one is valid
	w0, err := sf.Random(crand.Reader)
	require.NoError(tb, err)
	w1, err := sf.Random(crand.Reader)
	require.NoError(tb, err)

	x0 := base.ScalarMul(w0)
	x1, err := curve.Random(crand.Reader)
	require.NoError(tb, err)

	statement := sigor.CartesianComposeStatements(schnorr.NewStatement(x0), schnorr.NewStatement(x1))
	witness := sigor.CartesianComposeWitnesses(schnorr.NewWitness(w0), schnorr.NewWitness(w1))

	// Compose OR protocol
	orProtocol := sigor.CartesianCompose(protocol, protocol, prng)

	// Run protocol
	commitment, state, err := orProtocol.ComputeProverCommitment(statement, witness)
	require.NoError(tb, err)

	challenge := make([]byte, orProtocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(tb, err)

	response, err := orProtocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(tb, err)

	// Verify XOR constraint: e_0 XOR e_1 = challenge
	xored := make([]byte, len(challenge))
	subtle.XORBytes(xored, response.E0, response.E1)
	require.Equal(tb, challenge, xored, "XOR constraint should hold")
}
