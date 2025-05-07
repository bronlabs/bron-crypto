package schnorr_test

import (
	crand "crypto/rand"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
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
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		curve := edwards25519.NewCurve()
		testHappyPath(t, curve)
	})
	t.Run("pallas", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewPallasCurve()
		testHappyPath(t, curve)
	})
	t.Run("vesta", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewVestaCurve()
		testHappyPath(t, curve)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1Curve()
		testHappyPath(t, curve)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2Curve()
		testHappyPath(t, curve)
	})
}

func Test_InvalidStatement(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testInvalidStatement(t, curve)
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		curve := p256.NewCurve()
		testInvalidStatement(t, curve)
	})
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		curve := edwards25519.NewCurve()
		testInvalidStatement(t, curve)
	})
	t.Run("pallas", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewPallasCurve()
		testInvalidStatement(t, curve)
	})
	t.Run("vesta", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewVestaCurve()
		testInvalidStatement(t, curve)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1Curve()
		testInvalidStatement(t, curve)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2Curve()
		testInvalidStatement(t, curve)
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
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		curve := edwards25519.NewCurve()
		testSimulator(t, curve)
	})
	t.Run("pallas", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewPallasCurve()
		testSimulator(t, curve)
	})
	t.Run("vesta", func(t *testing.T) {
		t.Parallel()
		curve := pasta.NewVestaCurve()
		testSimulator(t, curve)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1Curve()
		testSimulator(t, curve)
	})
	t.Run("bls12381g2", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG2Curve()
		testSimulator(t, curve)
	})
}

func testHappyPath[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](t *testing.T, curve C) {
	t.Helper()

	base, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	protocol, err := schnorr.NewSigmaProtocol(base, crand.Reader)
	require.NoError(t, err)

	w, err := curve.ScalarField().Random(crand.Reader)
	require.NoError(t, err)
	x := base.ScalarMul(w)

	witness := schnorr.NewWitness(w)
	statement := schnorr.NewStatement(x)

	// round 1
	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)

	// round 2
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(t, err)

	// round 3
	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)

	// verify
	err = protocol.Verify(statement, commitment, challenge, response)
	require.NoError(t, err)
}

func testInvalidStatement[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](t *testing.T, curve C) {
	t.Helper()

	base, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	protocol, err := schnorr.NewSigmaProtocol(base, crand.Reader)
	require.NoError(t, err)

	w, err := curve.ScalarField().Random(crand.Reader)
	require.NoError(t, err)
	x, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	witness := schnorr.NewWitness(w)
	statement := schnorr.NewStatement(x)

	// round 1
	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)

	// round 2
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(t, err)

	// round 3
	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)

	// verify
	err = protocol.Verify(statement, commitment, challenge, response)
	require.Error(t, err)
}

func testSimulator[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](t *testing.T, curve C) {
	t.Helper()

	base, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	protocol, err := schnorr.NewSigmaProtocol(base, crand.Reader)
	require.NoError(t, err)

	x, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	statement := schnorr.NewStatement(x)

	// simulate
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(t, err)
	commitment, response, err := protocol.RunSimulator(statement, challenge)
	require.NoError(t, err)

	// verify
	err = protocol.Verify(statement, commitment, challenge, response)
	require.NoError(t, err)
}
