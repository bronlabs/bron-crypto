package sigor_test

import (
	"crypto/subtle"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
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

func Test_CartesianOr_ResponseBytesIncludeChallenges(t *testing.T) {
	t.Parallel()

	responseA := &sigor.ResponseCartesian[sigma.Response, sigma.Response]{
		E0: []byte("aa"),
		E1: []byte("bb"),
		Z0: testBytes("x"),
		Z1: testBytes("yz"),
	}
	responseB := &sigor.ResponseCartesian[sigma.Response, sigma.Response]{
		E0: []byte("cc"),
		E1: []byte("bb"),
		Z0: testBytes("x"),
		Z1: testBytes("yz"),
	}
	require.NotEqual(t, responseA.Bytes(), responseB.Bytes())
}

func Test_CartesianOr_VerifyRejectsMalformedChallenges(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	base, err := curve.Random(prng)
	require.NoError(t, err)
	protocol, err := schnorr.NewProtocol(base, prng)
	require.NoError(t, err)
	orProtocol, err := sigor.CartesianCompose(protocol, protocol, prng)
	require.NoError(t, err)

	sf, ok := curve.ScalarStructure().(algebra.PrimeField[*k256.Scalar])
	require.True(t, ok)
	w0, err := sf.Random(prng)
	require.NoError(t, err)
	w1, err := sf.Random(prng)
	require.NoError(t, err)

	statement, err := sigor.CartesianComposeStatements(
		schnorr.NewStatement(base.ScalarMul(w0)),
		schnorr.NewStatement(base),
	)
	require.NoError(t, err)
	witness, err := sigor.CartesianComposeWitnesses(schnorr.NewWitness(w0), schnorr.NewWitness(w1))
	require.NoError(t, err)
	commitment, state, err := orProtocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)

	challenge := make([]byte, orProtocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(t, err)

	response, err := orProtocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)
	response.E0 = response.E0[:1]

	require.NotPanics(t, func() {
		err = orProtocol.Verify(statement, commitment, challenge, response)
	})
	require.Error(t, err)
}

func testCartesianOrHappyPath[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	tb testing.TB, curve curves.Curve[P, F, S], validBranch int,
) {
	tb.Helper()

	prng := pcg.NewRandomised()
	base, err := curve.Random(pcg.NewRandomised())
	require.NoError(tb, err)

	protocol, err := schnorr.NewProtocol(base, prng)
	require.NoError(tb, err)

	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	require.True(tb, ok)

	// Create two witnesses - only one is valid
	w0, err := sf.Random(pcg.NewRandomised())
	require.NoError(tb, err)
	w1, err := sf.Random(pcg.NewRandomised())
	require.NoError(tb, err)

	var x0, x1 P
	if validBranch == 0 {
		x0 = base.ScalarMul(w0) // Valid
		x1, err = curve.Random(pcg.NewRandomised())
		require.NoError(tb, err) // Invalid
	} else {
		x0, err = curve.Random(pcg.NewRandomised())
		require.NoError(tb, err) // Invalid
		x1 = base.ScalarMul(w1)  // Valid
	}

	statement, err := sigor.CartesianComposeStatements(schnorr.NewStatement(x0), schnorr.NewStatement(x1))
	require.NoError(tb, err)
	witness, err := sigor.CartesianComposeWitnesses(schnorr.NewWitness(w0), schnorr.NewWitness(w1))
	require.NoError(tb, err)

	// Compose OR protocol
	orProtocol, err := sigor.CartesianCompose(protocol, protocol, prng)
	require.NoError(tb, err)

	// Round 1: Prover commitment
	commitment, state, err := orProtocol.ComputeProverCommitment(statement, witness)
	require.NoError(tb, err)

	// Round 2: Verifier challenge
	challenge := make([]byte, orProtocol.GetChallengeBytesLength())
	_, err = io.ReadFull(pcg.NewRandomised(), challenge)
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

	prng := pcg.NewRandomised()
	base, err := curve.Random(pcg.NewRandomised())
	require.NoError(tb, err)

	protocol, err := schnorr.NewProtocol(base, prng)
	require.NoError(tb, err)

	// Create random statements (no valid witnesses)
	x0, err := curve.Random(pcg.NewRandomised())
	require.NoError(tb, err)
	x1, err := curve.Random(pcg.NewRandomised())
	require.NoError(tb, err)

	statement, err := sigor.CartesianComposeStatements(schnorr.NewStatement(x0), schnorr.NewStatement(x1))
	require.NoError(tb, err)

	// Compose OR protocol
	orProtocol, err := sigor.CartesianCompose(protocol, protocol, prng)
	require.NoError(tb, err)

	// Generate random challenge
	challenge := make([]byte, orProtocol.GetChallengeBytesLength())
	_, err = io.ReadFull(pcg.NewRandomised(), challenge)
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

	prng := pcg.NewRandomised()
	base, err := curve.Random(pcg.NewRandomised())
	require.NoError(tb, err)

	protocol, err := schnorr.NewProtocol(base, prng)
	require.NoError(tb, err)

	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	require.True(tb, ok)

	// Create two witnesses - first one is valid
	w0, err := sf.Random(pcg.NewRandomised())
	require.NoError(tb, err)
	w1, err := sf.Random(pcg.NewRandomised())
	require.NoError(tb, err)

	x0 := base.ScalarMul(w0)
	x1, err := curve.Random(pcg.NewRandomised())
	require.NoError(tb, err)

	statement, err := sigor.CartesianComposeStatements(schnorr.NewStatement(x0), schnorr.NewStatement(x1))
	require.NoError(tb, err)
	witness, err := sigor.CartesianComposeWitnesses(schnorr.NewWitness(w0), schnorr.NewWitness(w1))
	require.NoError(tb, err)

	// Compose OR protocol
	orProtocol, err := sigor.CartesianCompose(protocol, protocol, prng)
	require.NoError(tb, err)

	// Run protocol
	commitment, state, err := orProtocol.ComputeProverCommitment(statement, witness)
	require.NoError(tb, err)

	challenge := make([]byte, orProtocol.GetChallengeBytesLength())
	_, err = io.ReadFull(pcg.NewRandomised(), challenge)
	require.NoError(tb, err)

	response, err := orProtocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(tb, err)

	// Verify XOR constraint: e_0 XOR e_1 = challenge
	xored := make([]byte, len(challenge))
	subtle.XORBytes(xored, response.E0, response.E1)
	require.Equal(tb, challenge, xored, "XOR constraint should hold")
}

func Test_CartesianOr_SpecialSoundness(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	protocol, err := schnorr.NewProtocol(k256.NewCurve().Generator(), prng)
	require.NoError(t, err)

	for _, tc := range []struct {
		k0, k1, want uint
	}{
		{k0: 2, k1: 2, want: 2},
		{k0: 3, k1: 2, want: 3},
		{k0: 2, k1: 3, want: 3},
		{k0: 3, k1: 3, want: 5},
		{k0: 4, k1: 3, want: 7},
	} {
		orProtocol, err := sigor.CartesianCompose(&kSpecialSound{protocol, tc.k0}, &kSpecialSound{protocol, tc.k1}, prng)
		require.NoError(t, err)
		require.Equal(t, tc.want, orProtocol.SpecialSoundness(), "k0 = %d, k1 = %d", tc.k0, tc.k1)
	}
}

// Test_CartesianOr_RejectsMismatchedChallengeLengths: a branch that reads only a prefix
// of the shared challenge leaves the remaining bytes free for the prover, which breaks
// special soundness of the composition.
func Test_CartesianOr_RejectsMismatchedChallengeLengths(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	protocol, err := schnorr.NewProtocol(k256.NewCurve().Generator(), prng)
	require.NoError(t, err)

	_, err = sigor.CartesianCompose(protocol, &shortChallenge{protocol}, prng)
	require.ErrorIs(t, err, sigor.ErrInvalidArgument)
	_, err = sigor.CartesianCompose(&shortChallenge{protocol}, protocol, prng)
	require.ErrorIs(t, err, sigor.ErrInvalidArgument)
}

// Test_CartesianOr_VerifyRejectsMissingBranchChallenges: empty branch challenges XOR to
// the all-zero string, so an all-zero verifier challenge (the first one tried by the
// fischlin prover) passed the XOR check and the verifier then indexed past the empty
// slices. The verifier must reject them instead.
func Test_CartesianOr_VerifyRejectsMissingBranchChallenges(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	base, err := curve.Random(prng)
	require.NoError(t, err)
	protocol, err := schnorr.NewProtocol(base, prng)
	require.NoError(t, err)
	orProtocol, err := sigor.CartesianCompose(protocol, protocol, prng)
	require.NoError(t, err)

	sf, ok := curve.ScalarStructure().(algebra.PrimeField[*k256.Scalar])
	require.True(t, ok)
	w0, err := sf.Random(prng)
	require.NoError(t, err)
	w1, err := sf.Random(prng)
	require.NoError(t, err)

	statement, err := sigor.CartesianComposeStatements(
		schnorr.NewStatement(base.ScalarMul(w0)),
		schnorr.NewStatement(base),
	)
	require.NoError(t, err)
	witness, err := sigor.CartesianComposeWitnesses(schnorr.NewWitness(w0), schnorr.NewWitness(w1))
	require.NoError(t, err)
	commitment, state, err := orProtocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)

	challenge := make([]byte, orProtocol.GetChallengeBytesLength())
	response, err := orProtocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)
	require.NoError(t, orProtocol.Verify(statement, commitment, challenge, response))

	for _, tc := range []struct {
		name   string
		e0, e1 []byte
	}{
		{name: "both empty", e0: nil, e1: nil},
		{name: "e0 empty", e0: nil, e1: make([]byte, len(response.E1))},
		{name: "e1 empty", e0: make([]byte, len(response.E0)), e1: nil},
		{name: "e0 short", e0: response.E0[:1], e1: response.E1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			malformed := *response
			malformed.E0 = tc.e0
			malformed.E1 = tc.e1
			var err error
			require.NotPanics(t, func() {
				err = orProtocol.Verify(statement, commitment, challenge, &malformed)
			})
			require.ErrorIs(t, err, sigor.ErrInvalidLength)
		})
	}
}
