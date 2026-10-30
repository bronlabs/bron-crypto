package schnorr_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testHappyPath(t, curve)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testHappyPath(t, curve)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		testHappyPath(t, curve)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2()
		testHappyPath(t, curve)
	})
}

func Test_Simulator(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testSimulator(t, curve)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testSimulator(t, curve)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		testSimulator(t, curve)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2()
		testSimulator(t, curve)
	})
}

func Test_Anchor(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		testAnchor(t, k256.NewCurve())
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		testAnchor(t, p256.NewCurve())
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		testAnchor(t, bls12381.NewG1())
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		testAnchor(t, bls12381.NewG2())
	})
}

func Test_Extractor(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testExtractor(t, curve)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testExtractor(t, curve)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		testExtractor(t, curve)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2()
		testExtractor(t, curve)
	})
}

func testHappyPath[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](tb testing.TB, curve curves.Curve[P, F, S]) {
	tb.Helper()

	prng := pcg.NewRandomised()
	base, err := curve.Random(pcg.NewRandomised())
	require.NoError(tb, err)

	protocol, err := schnorr.NewProtocol(base, prng)
	require.NoError(tb, err)

	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	require.True(tb, ok)
	w, err := sf.Random(pcg.NewRandomised())
	require.NoError(tb, err)
	x := base.ScalarMul(w)

	witness := schnorr.NewWitness(w)
	statement := schnorr.NewStatement(x)

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

func testSimulator[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](tb testing.TB, curve curves.Curve[P, F, S]) {
	tb.Helper()

	base, err := curve.Random(pcg.NewRandomised())
	require.NoError(tb, err)

	protocol, err := schnorr.NewProtocol(base, pcg.NewRandomised())
	require.NoError(tb, err)

	x, err := curve.Random(pcg.NewRandomised())
	require.NoError(tb, err)

	statement := schnorr.NewStatement(x)

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

func testAnchor[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](tb testing.TB, curve curves.Curve[P, F, S]) {
	tb.Helper()

	prng := pcg.NewRandomised()
	generator, err := curve.Random(prng)
	require.NoError(tb, err)

	protocol, err := schnorr.NewProtocol(generator, prng)
	require.NoError(tb, err)

	anchor := protocol.Anchor()

	// L() is the group order.
	expectedL, err := num.N().FromBytes(curve.Order().Bytes())
	require.NoError(tb, err)
	require.True(tb, anchor.L().Equal(expectedL))

	// PreImage(x) is the scalar-field zero for every x.
	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	require.True(tb, ok)
	for range 8 {
		x, err := curve.Random(pcg.NewRandomised())
		require.NoError(tb, err)
		require.True(tb, anchor.PreImage(x).Equal(sf.Zero()))
	}

	// Anchor invariant: phi(PreImage(x)) == x * L(). Both sides must equal the group identity.
	phi := protocol.Phi()
	for range 8 {
		x, err := curve.Random(pcg.NewRandomised())
		require.NoError(tb, err)
		lhs, err := phi(anchor.PreImage(x))
		require.NoError(tb, err)
		rhs := algebrautils.ScalarMul(x, anchor.L())
		require.True(tb, lhs.Equal(rhs))
	}
}

func testExtractor[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](tb testing.TB, curve curves.Curve[P, F, S]) {
	tb.Helper()

	prng := pcg.NewRandomised()
	base, err := curve.Random(pcg.NewRandomised())
	require.NoError(tb, err)

	protocol, err := schnorr.NewProtocol(base, prng)
	require.NoError(tb, err)

	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	require.True(tb, ok)
	w, err := sf.Random(pcg.NewRandomised())
	require.NoError(tb, err)
	x := base.ScalarMul(w)

	witness := schnorr.NewWitness(w)
	statement := schnorr.NewStatement(x)

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
	zi := []*schnorr.Response[S]{response1, response2}

	wExtracted, err := protocol.Extract(statement, commitment, ei, zi)
	require.NoError(tb, err)
	require.True(tb, wExtracted.Value().Equal(witness.Value()))
}

func Test_ChallengeLength(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	curve := k256.NewCurve()
	protocol, err := schnorr.NewProtocol(curve.Generator(), prng)
	require.NoError(t, err)

	w, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	witness := schnorr.NewWitness(w)
	statement := schnorr.NewStatement(curve.ScalarBaseMul(w))

	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(t, err)
	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)
	require.NoError(t, protocol.Verify(statement, commitment, challenge, response))

	// Leading zero bytes parse to the same scalar but are a non-canonical encoding.
	padded := append([]byte{0x00}, challenge...)
	require.Error(t, protocol.Verify(statement, commitment, padded, response))
	_, err = protocol.ComputeProverResponse(statement, witness, commitment, state, padded)
	require.Error(t, err)

	truncated := challenge[1:]
	require.Error(t, protocol.Verify(statement, commitment, truncated, response))
	_, err = protocol.ComputeProverResponse(statement, witness, commitment, state, truncated)
	require.Error(t, err)
}

// Test_Verify_NilMessagesRejected checks that a missing commitment or response
// fails verification instead of crashing the verifier. Both values are chosen by
// the prover and arrive over the wire, whichever compiler or interactive
// verifier is in use. Schnorr works over a plain group, so a missing value is
// the only malformed shape a decoder can hand over.
func Test_Verify_NilMessagesRejected(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		testNilMessagesRejected(t, k256.NewCurve())
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		testNilMessagesRejected(t, p256.NewCurve())
	})
}

func testNilMessagesRejected[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](tb testing.TB, curve curves.Curve[P, F, S]) {
	tb.Helper()

	prng := pcg.NewRandomised()
	base, err := curve.Random(prng)
	require.NoError(tb, err)
	protocol, err := schnorr.NewProtocol(base, prng)
	require.NoError(tb, err)

	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	require.True(tb, ok)
	w, err := sf.Random(prng)
	require.NoError(tb, err)
	witness := schnorr.NewWitness(w)
	statement := schnorr.NewStatement(base.ScalarMul(w))

	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(tb, err)
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(tb, err)
	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(tb, err)
	require.NoError(tb, protocol.Verify(statement, commitment, challenge, response))

	var nilCommitment P
	var verifyErr error
	require.NotPanics(tb, func() {
		verifyErr = protocol.Verify(statement, &schnorr.Commitment[P, S]{A: nilCommitment}, challenge, response)
	})
	require.ErrorIs(tb, verifyErr, proofs.ErrVerificationFailed)

	var nilResponse S
	require.NotPanics(tb, func() {
		verifyErr = protocol.Verify(statement, commitment, challenge, &schnorr.Response[S]{Z: nilResponse})
	})
	require.ErrorIs(tb, verifyErr, proofs.ErrVerificationFailed)
}
