package sigand_test

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compose/sigand"
	"github.com/stretchr/testify/require"
)

func Test_CartesianAnd_HappyPath(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testCartesianAndHappyPath(t, curve)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testCartesianAndHappyPath(t, curve)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		testCartesianAndHappyPath(t, curve)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2()
		testCartesianAndHappyPath(t, curve)
	})
}

func Test_CartesianAnd_Simulator(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testCartesianAndSimulator(t, curve)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testCartesianAndSimulator(t, curve)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		testCartesianAndSimulator(t, curve)
	})
}

func testCartesianAndHappyPath[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
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

	// Create two valid witnesses - BOTH must be valid for AND composition
	w0, err := sf.Random(crand.Reader)
	require.NoError(tb, err)
	w1, err := sf.Random(crand.Reader)
	require.NoError(tb, err)

	x0 := base.ScalarMul(w0)
	x1 := base.ScalarMul(w1)

	statement := sigand.CartesianComposeStatements(schnorr.NewStatement(x0), schnorr.NewStatement(x1))
	witness := sigand.CartesianComposeWitnesses(schnorr.NewWitness(w0), schnorr.NewWitness(w1))

	// Compose AND protocol
	andProtocol := sigand.CartesianCompose(protocol, protocol)

	// Validate all statements
	err = andProtocol.ValidateStatement(statement, witness)
	require.NoError(tb, err)

	// Round 1: Prover commitment
	commitment, state, err := andProtocol.ComputeProverCommitment(statement, witness)
	require.NoError(tb, err)

	// Round 2: Verifier challenge
	challenge := make([]byte, andProtocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(tb, err)

	// Round 3: Prover response
	response, err := andProtocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(tb, err)

	// Verify
	err = andProtocol.Verify(statement, commitment, challenge, response)
	require.NoError(tb, err)
}

func testCartesianAndSimulator[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S],
) {
	tb.Helper()

	prng := crand.Reader
	base, err := curve.Random(crand.Reader)
	require.NoError(tb, err)

	protocol, err := schnorr.NewProtocol(base, prng)
	require.NoError(tb, err)

	// Create random statements (no valid witnesses needed for simulator)
	x0, err := curve.Random(crand.Reader)
	require.NoError(tb, err)
	x1, err := curve.Random(crand.Reader)
	require.NoError(tb, err)

	statement := sigand.CartesianComposeStatements(schnorr.NewStatement(x0), schnorr.NewStatement(x1))

	// Compose AND protocol
	andProtocol := sigand.CartesianCompose(protocol, protocol)

	// Generate random challenge
	challenge := make([]byte, andProtocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(tb, err)

	// Run simulator
	commitment, response, err := andProtocol.RunSimulator(statement, challenge)
	require.NoError(tb, err)

	// Verify simulated proof
	err = andProtocol.Verify(statement, commitment, challenge, response)
	require.NoError(tb, err)
}
