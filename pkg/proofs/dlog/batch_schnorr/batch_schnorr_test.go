package batch_schnorr_test

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr"
	"github.com/stretchr/testify/require"
)

func Test_BatchSchnorr_HappyPath(t *testing.T) {
	t.Parallel()

	batchSizes := []uint{2, 3, 5, 10}

	for _, batchSize := range batchSizes {
		t.Run("k256", func(t *testing.T) {
			t.Parallel()
			curve := k256.NewCurve()
			testBatchHappyPath(t, curve, batchSize)
		})
		t.Run("p256", func(t *testing.T) {
			t.Parallel()
			curve := p256.NewCurve()
			testBatchHappyPath(t, curve, batchSize)
		})
		t.Run("bls12381g1", func(t *testing.T) {
			t.Parallel()
			curve := bls12381.NewG1()
			testBatchHappyPath(t, curve, batchSize)
		})
		t.Run("bls12381g2", func(t *testing.T) {
			t.Parallel()
			curve := bls12381.NewG2()
			testBatchHappyPath(t, curve, batchSize)
		})
	}
}

func Test_BatchSchnorr_InvalidStatement(t *testing.T) {
	t.Parallel()

	batchSizes := []uint{2, 5}

	for _, batchSize := range batchSizes {
		t.Run("k256", func(t *testing.T) {
			t.Parallel()
			curve := k256.NewCurve()
			testBatchInvalidStatement(t, curve, batchSize)
		})
		t.Run("p256", func(t *testing.T) {
			t.Parallel()
			curve := p256.NewCurve()
			testBatchInvalidStatement(t, curve, batchSize)
		})
		t.Run("bls12381g1", func(t *testing.T) {
			t.Parallel()
			curve := bls12381.NewG1()
			testBatchInvalidStatement(t, curve, batchSize)
		})
		t.Run("bls12381g2", func(t *testing.T) {
			t.Parallel()
			curve := bls12381.NewG2()
			testBatchInvalidStatement(t, curve, batchSize)
		})
	}
}

func Test_BatchSchnorr_Simulator(t *testing.T) {
	t.Parallel()

	batchSizes := []uint{2, 3, 4}

	for _, batchSize := range batchSizes {
		t.Run("k256", func(t *testing.T) {
			t.Parallel()
			curve := k256.NewCurve()
			testBatchSimulator(t, curve, batchSize)
		})
		t.Run("p256", func(t *testing.T) {
			t.Parallel()
			curve := p256.NewCurve()
			testBatchSimulator(t, curve, batchSize)
		})
		t.Run("bls12381g1", func(t *testing.T) {
			t.Parallel()
			curve := bls12381.NewG1()
			testBatchSimulator(t, curve, batchSize)
		})
		t.Run("bls12381g2", func(t *testing.T) {
			t.Parallel()
			curve := bls12381.NewG2()
			testBatchSimulator(t, curve, batchSize)
		})
	}
}

func Test_BatchSchnorr_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("BatchSize1", func(t *testing.T) {
		// Test with batch size 1 (should work similar to regular Schnorr)
		curve := k256.NewCurve()
		testBatchHappyPath(t, curve, 1)
	})

	t.Run("NilPRNG", func(t *testing.T) {
		// Test that nil PRNG defaults to crypto/rand.Reader
		curve := p256.NewCurve()
		base, err := curve.Random(crand.Reader)
		require.NoError(t, err)

		protocol, err := batch_schnorr.NewSigmaProtocol(base, 3, nil)
		require.NoError(t, err)
		require.NotNil(t, protocol)
	})

	t.Run("ZeroCoefficientsInWitness", func(t *testing.T) {
		// Test with witness polynomial that has some zero coefficients
		curve := bls12381.NewG1()
		testBatchWithZeroCoefficients(t, curve, 5)
	})
}

func Test_BatchSchnorr_PartiallyCorrectWitness(t *testing.T) {
	t.Parallel()

	// Test where only some coefficients of the witness polynomial are correct
	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		testBatchPartiallyCorrectWitness(t, curve, 4)
	})
	t.Run("bls12381g1", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		testBatchPartiallyCorrectWitness(t, curve, 4)
	})
}

func testBatchHappyPath[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	t *testing.T, curve interface {
		curves.Curve[P, F, S]
		algebra.FiniteStructure[P]
	}, batchSize uint,
) {
	t.Helper()

	base, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	protocol, err := batch_schnorr.NewSigmaProtocol(base, batchSize, crand.Reader)
	require.NoError(t, err)

	// Create witness polynomial with random coefficients
	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	require.True(t, ok)
	polyRing, err := polynomials.NewPolynomialRing(sf)
	require.NoError(t, err)

	// Generate random witness polynomial of degree batchSize-1
	witnessCoeffs := make([]S, batchSize)
	for i := range witnessCoeffs {
		witnessCoeffs[i], err = sf.Random(crand.Reader)
		require.NoError(t, err)
	}
	witnessPoly, err := polyRing.New(witnessCoeffs...)
	require.NoError(t, err)

	// Compute statement polynomial: X = base^W (coefficient-wise)
	statementPoly, err := polynomials.LiftToExponent(witnessPoly, base)
	require.NoError(t, err)

	witness := &batch_schnorr.Witness[S]{W: witnessPoly}
	statement := &batch_schnorr.Statement[P, S]{
		X:   statementPoly,
		Phi: batch_schnorr.Phi(base),
	}

	// Round 1: Prover commitment
	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)
	require.NotNil(t, commitment)
	require.NotNil(t, state)

	// Round 2: Challenge
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(t, err)

	// Round 3: Prover response
	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)
	require.NotNil(t, response)

	// Verify
	err = protocol.Verify(statement, commitment, challenge, response)
	require.NoError(t, err)
}

func testBatchInvalidStatement[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	t *testing.T, curve curves.Curve[P, F, S], batchSize uint,
) {
	t.Helper()

	base, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	protocol, err := batch_schnorr.NewSigmaProtocol(base, batchSize, crand.Reader)
	require.NoError(t, err)

	// Create witness polynomial with random coefficients
	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	require.True(t, ok)
	polyRing, err := polynomials.NewPolynomialRing(sf)
	require.NoError(t, err)

	// Generate random witness polynomial
	witnessCoeffs := make([]S, batchSize)
	for i := range witnessCoeffs {
		witnessCoeffs[i], err = sf.Random(crand.Reader)
		require.NoError(t, err)
	}
	witnessPoly, err := polyRing.New(witnessCoeffs...)
	require.NoError(t, err)

	// Create INCORRECT statement polynomial (random instead of base^W)
	statementCoeffs := make([]P, batchSize)
	for i := range statementCoeffs {
		statementCoeffs[i], err = curve.Random(crand.Reader)
		require.NoError(t, err)
	}
	polyModule, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	statementPoly, err := polyModule.New(statementCoeffs...)
	require.NoError(t, err)

	witness := &batch_schnorr.Witness[S]{W: witnessPoly}
	statement := &batch_schnorr.Statement[P, S]{
		X:   statementPoly,
		Phi: batch_schnorr.Phi(base),
	}

	// Round 1: Prover commitment
	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)

	// Round 2: Challenge
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(t, err)

	// Round 3: Prover response
	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)

	// Verify should fail
	err = protocol.Verify(statement, commitment, challenge, response)
	require.Error(t, err)
}

func testBatchSimulator[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	t *testing.T, curve curves.Curve[P, F, S], batchSize uint,
) {
	t.Helper()

	base, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	protocol, err := batch_schnorr.NewSigmaProtocol(base, batchSize, crand.Reader)
	require.NoError(t, err)

	// Create random statement polynomial (without knowing witness)
	polyModule, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	statementCoeffs := make([]P, batchSize)
	for i := range statementCoeffs {
		statementCoeffs[i], err = curve.Random(crand.Reader)
		require.NoError(t, err)
	}
	statementPoly, err := polyModule.New(statementCoeffs...)
	require.NoError(t, err)

	statement := &batch_schnorr.Statement[P, S]{
		X:   statementPoly,
		Phi: batch_schnorr.Phi(base),
	}

	// Simulate
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(t, err)

	commitment, response, err := protocol.RunSimulator(statement, challenge)
	require.NoError(t, err)
	require.NotNil(t, commitment)
	require.NotNil(t, response)

	// Verify simulated proof
	err = protocol.Verify(statement, commitment, challenge, response)
	require.NoError(t, err)
}

func testBatchWithZeroCoefficients[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	t *testing.T, curve curves.Curve[P, F, S], batchSize uint,
) {
	t.Helper()

	base, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	protocol, err := batch_schnorr.NewSigmaProtocol(base, batchSize, crand.Reader)
	require.NoError(t, err)

	// Create witness polynomial with some zero coefficients
	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	require.True(t, ok)
	polyRing, err := polynomials.NewPolynomialRing(sf)
	require.NoError(t, err)

	witnessCoeffs := make([]S, batchSize)
	for i := range witnessCoeffs {
		if i%2 == 0 {
			witnessCoeffs[i] = sf.Zero()
		} else {
			witnessCoeffs[i], err = sf.Random(crand.Reader)
			require.NoError(t, err)
		}
	}
	// Ensure at least one non-zero coefficient
	if witnessCoeffs[1].IsZero() {
		witnessCoeffs[1] = sf.One()
	}
	witnessPoly, err := polyRing.New(witnessCoeffs...)
	require.NoError(t, err)

	// Compute statement polynomial
	statementPoly, err := polynomials.LiftToExponent(witnessPoly, base)
	require.NoError(t, err)

	witness := &batch_schnorr.Witness[S]{W: witnessPoly}
	statement := &batch_schnorr.Statement[P, S]{
		X:   statementPoly,
		Phi: batch_schnorr.Phi(base),
	}

	// Complete protocol
	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(t, err)

	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)

	err = protocol.Verify(statement, commitment, challenge, response)
	require.NoError(t, err)
}

func testBatchPartiallyCorrectWitness[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]](
	t *testing.T, curve curves.Curve[P, F, S], batchSize uint,
) {
	t.Helper()

	base, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	protocol, err := batch_schnorr.NewSigmaProtocol(base, batchSize, crand.Reader)
	require.NoError(t, err)

	// Create witness polynomial
	sf, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	require.True(t, ok)
	polyRing, err := polynomials.NewPolynomialRing(sf)
	require.NoError(t, err)

	witnessCoeffs := make([]S, batchSize)
	for i := range witnessCoeffs {
		witnessCoeffs[i], err = sf.Random(crand.Reader)
		require.NoError(t, err)
	}
	witnessPoly, err := polyRing.New(witnessCoeffs...)
	require.NoError(t, err)

	// Compute correct statement polynomial first
	correctStatementPoly, err := polynomials.LiftToExponent(witnessPoly, base)
	require.NoError(t, err)

	// Now modify some coefficients of the statement to make it partially incorrect
	polyModule, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	statementCoeffs := correctStatementPoly.Coefficients()
	// Modify half of the coefficients
	for i := 0; i < len(statementCoeffs)/2; i++ {
		randomPoint, err := curve.Random(crand.Reader)
		require.NoError(t, err)
		statementCoeffs[i] = randomPoint
	}
	incorrectStatementPoly, err := polyModule.New(statementCoeffs...)
	require.NoError(t, err)

	witness := &batch_schnorr.Witness[S]{W: witnessPoly}
	statement := &batch_schnorr.Statement[P, S]{
		X:   incorrectStatementPoly,
		Phi: batch_schnorr.Phi(base),
	}

	// Complete protocol
	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(t, err)

	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)

	// Verify should fail
	err = protocol.Verify(statement, commitment, challenge, response)
	require.Error(t, err)
}

// Test_BatchSchnorr_ProtocolName tests that the protocol name is correct
func Test_BatchSchnorr_ProtocolName(t *testing.T) {
	curve := k256.NewCurve()
	base, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	protocol, err := batch_schnorr.NewSigmaProtocol(base, 3, crand.Reader)
	require.NoError(t, err)

	name := protocol.Name()
	require.Equal(t, batch_schnorr.Name, name)
	require.Contains(t, string(name), "BATCH_SCHNORR-dlog_pok-")
}

// Test_BatchSchnorr_ConsistencyAcrossBatchSizes tests that single proofs can be verified as batch proofs
func Test_BatchSchnorr_ConsistencyAcrossBatchSizes(t *testing.T) {
	t.Parallel()

	curve := p256.NewCurve()
	base, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	// Create a single witness
	sf, ok := curve.ScalarStructure().(algebra.PrimeField[*p256.Scalar])
	require.True(t, ok)
	witness, err := sf.Random(crand.Reader)
	require.NoError(t, err)
	statement := base.ScalarMul(witness)

	// Test as batch size 1
	protocol1, err := batch_schnorr.NewSigmaProtocol(base, 1, crand.Reader)
	require.NoError(t, err)

	polyRing, err := polynomials.NewPolynomialRing(sf)
	require.NoError(t, err)
	witnessPoly1, err := polyRing.New(witness)
	require.NoError(t, err)

	polyModule, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)
	statementPoly1, err := polyModule.New(statement)
	require.NoError(t, err)

	batchWitness1 := &batch_schnorr.Witness[*p256.Scalar]{W: witnessPoly1}
	batchStatement1 := &batch_schnorr.Statement[*p256.Point, *p256.Scalar]{
		X:   statementPoly1,
		Phi: batch_schnorr.Phi(base),
	}

	// Generate proof
	commitment1, state1, err := protocol1.ComputeProverCommitment(batchStatement1, batchWitness1)
	require.NoError(t, err)

	challenge := make([]byte, protocol1.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(t, err)

	response1, err := protocol1.ComputeProverResponse(batchStatement1, batchWitness1, commitment1, state1, challenge)
	require.NoError(t, err)

	// Verify
	err = protocol1.Verify(batchStatement1, commitment1, challenge, response1)
	require.NoError(t, err)
}
