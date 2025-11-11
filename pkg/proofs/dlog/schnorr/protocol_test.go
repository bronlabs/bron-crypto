package schnorr_test

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
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/stretchr/testify/require"
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

func Test_Extractor(t *testing.T) {
	t.Parallel()

	for range 1024 {
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
}

func testHappyPath[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](tb testing.TB, curve curves.Curve[P, F, S]) {
	tb.Helper()

	prng := crand.Reader
	base, err := curve.Random(crand.Reader)
	require.NoError(tb, err)

	protocol, err := schnorr.NewProtocol(base, prng)
	require.NoError(tb, err)

	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	require.True(tb, ok)
	w, err := sf.Random(crand.Reader)
	require.NoError(tb, err)
	x := base.ScalarMul(w)

	witness := schnorr.NewWitness(w)
	statement := schnorr.NewStatement(x)

	// round 1
	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(tb, err)

	// round 2
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
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

	base, err := curve.Random(crand.Reader)
	require.NoError(tb, err)

	protocol, err := schnorr.NewProtocol(base, crand.Reader)
	require.NoError(tb, err)

	x, err := curve.Random(crand.Reader)
	require.NoError(tb, err)

	statement := schnorr.NewStatement(x)

	// simulate
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(tb, err)
	commitment, response, err := protocol.RunSimulator(statement, challenge)
	require.NoError(tb, err)

	// verify
	err = protocol.Verify(statement, commitment, challenge, response)
	require.NoError(tb, err)
}

func testExtractor[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](tb testing.TB, curve curves.Curve[P, F, S]) {
	tb.Helper()

	prng := crand.Reader
	base, err := curve.Random(crand.Reader)
	require.NoError(tb, err)

	protocol, err := schnorr.NewProtocol(base, prng)
	require.NoError(tb, err)

	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	require.True(tb, ok)
	w, err := sf.Random(crand.Reader)
	require.NoError(tb, err)
	x := base.ScalarMul(w)

	witness := schnorr.NewWitness(w)
	statement := schnorr.NewStatement(x)

	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(tb, err)

	challenge1 := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge1)
	require.NoError(tb, err)
	challenge2 := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge2)
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
