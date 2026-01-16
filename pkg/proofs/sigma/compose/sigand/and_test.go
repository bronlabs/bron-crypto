package sigand_test

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compose/sigand"
)

func Test_And_HappyPath(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testAndHappyPath(t, curve, 2)
		testAndHappyPath(t, curve, 3)
		testAndHappyPath(t, curve, 5)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testAndHappyPath(t, curve, 2)
		testAndHappyPath(t, curve, 3)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		testAndHappyPath(t, curve, 2)
		testAndHappyPath(t, curve, 3)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2()
		testAndHappyPath(t, curve, 2)
	})
}

func Test_And_Simulator(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testAndSimulator(t, curve, 2)
		testAndSimulator(t, curve, 3)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testAndSimulator(t, curve, 2)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		testAndSimulator(t, curve, 2)
	})
}

func Test_And_InvalidInputs(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	base, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	protocol, err := schnorr.NewProtocol(base, crand.Reader)
	require.NoError(t, err)

	t.Run("nil_protocol", func(t *testing.T) {
		_, err := sigand.Compose[*schnorr.Statement[*k256.Point, *k256.Scalar], *schnorr.Witness[*k256.Scalar], *schnorr.Commitment[*k256.Point, *k256.Scalar], *schnorr.State[*k256.Scalar], *schnorr.Response[*k256.Scalar]](nil, 2)
		require.Error(t, err)
	})

	t.Run("count_zero", func(t *testing.T) {
		_, err := sigand.Compose(protocol, 0)
		require.Error(t, err)
	})
}

func testAndHappyPath[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
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

	// Create statements and witnesses - ALL must be valid for AND composition
	statements := make(sigand.Statement[*schnorr.Statement[P, S]], count)
	witnesses := make(sigand.Witness[*schnorr.Witness[S]], count)

	for i := range count {
		w, err := sf.Random(crand.Reader)
		require.NoError(tb, err)

		x := base.ScalarMul(w)
		statements[i] = schnorr.NewStatement(x)
		witnesses[i] = schnorr.NewWitness(w)
	}

	// Compose AND protocol
	andProtocol, err := sigand.Compose(protocol, count)
	require.NoError(tb, err)

	// Validate all statements
	err = andProtocol.ValidateStatement(statements, witnesses)
	require.NoError(tb, err)

	// Round 1: Prover commitment
	commitment, state, err := andProtocol.ComputeProverCommitment(statements, witnesses)
	require.NoError(tb, err)

	// Round 2: Verifier challenge
	challenge := make([]byte, andProtocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(tb, err)

	// Round 3: Prover response
	response, err := andProtocol.ComputeProverResponse(statements, witnesses, commitment, state, challenge)
	require.NoError(tb, err)

	// Verify
	err = andProtocol.Verify(statements, commitment, challenge, response)
	require.NoError(tb, err)
}

func testAndSimulator[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S], count uint,
) {
	tb.Helper()

	prng := crand.Reader
	base, err := curve.Random(crand.Reader)
	require.NoError(tb, err)

	protocol, err := schnorr.NewProtocol(base, prng)
	require.NoError(tb, err)

	// Create random statements (no valid witnesses needed for simulator)
	statements := make(sigand.Statement[*schnorr.Statement[P, S]], count)
	for i := range count {
		x, err := curve.Random(crand.Reader)
		require.NoError(tb, err)
		statements[i] = schnorr.NewStatement(x)
	}

	// Compose AND protocol
	andProtocol, err := sigand.Compose(protocol, count)
	require.NoError(tb, err)

	// Generate random challenge
	challenge := make([]byte, andProtocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(tb, err)

	// Run simulator
	commitment, response, err := andProtocol.RunSimulator(statements, challenge)
	require.NoError(tb, err)

	// Verify simulated proof
	err = andProtocol.Verify(statements, commitment, challenge, response)
	require.NoError(tb, err)
}
