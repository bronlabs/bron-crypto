package maurer09_test

import (
	crand "crypto/rand"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/num"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/num/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/proofs/maurer09"
	"github.com/stretchr/testify/require"
)

// TestMaurer09Protocol_BasicFunctionality tests the basic protocol flow
func TestMaurer09Protocol_BasicFunctionality(t *testing.T) {
	t.Parallel()

	// Setup using k256 curve as an example
	curve := k256.NewCurve()
	basePoint, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	// Define the homomorphism: scalar multiplication
	phi := func(s *k256.Scalar) *k256.Point {
		return basePoint.ScalarMul(s)
	}

	// Get scalar field
	scalarField := curve.ScalarStructure().(algebra.PrimeField[*k256.Scalar])

	// Define challenge actions
	challengeActionOnPreImage := func(c *k256.Scalar, x *k256.Scalar) *k256.Scalar {
		return x.Mul(c)
	}
	challengeActionOnImage := func(c *k256.Scalar, x *k256.Point) *k256.Point {
		return x.ScalarMul(c)
	}

	// Create protocol
	protocol, err := maurer09.NewProtocol(
		phi,
		scalarField,
		curve,
		scalarField,
		challengeActionOnPreImage,
		challengeActionOnImage,
		scalarField.Random,
		crand.Reader,
	)
	require.NoError(t, err)

	// Create witness and statement
	witness, err := scalarField.Random(crand.Reader)
	require.NoError(t, err)
	statement := phi(witness)

	w := &maurer09.Witness[*k256.Scalar]{W: witness}
	s := &maurer09.Statement[*k256.Scalar, *k256.Point]{
		X:   statement,
		Phi: phi,
	}

	// Run protocol
	commitment, state, err := protocol.ComputeProverCommitment(s, w)
	require.NoError(t, err)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(t, err)

	response, err := protocol.ComputeProverResponse(s, w, commitment, state, challenge)
	require.NoError(t, err)

	// Verify
	err = protocol.Verify(s, commitment, challenge, response)
	require.NoError(t, err)
}

// TestMaurer09Protocol_InvalidWitness tests verification failure with invalid witness
func TestMaurer09Protocol_InvalidWitness(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	basePoint, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	phi := func(s *k256.Scalar) *k256.Point {
		return basePoint.ScalarMul(s)
	}

	scalarField := curve.ScalarStructure().(algebra.PrimeField[*k256.Scalar])

	challengeActionOnPreImage := func(c *k256.Scalar, x *k256.Scalar) *k256.Scalar {
		return x.Mul(c)
	}
	challengeActionOnImage := func(c *k256.Scalar, x *k256.Point) *k256.Point {
		return x.ScalarMul(c)
	}

	protocol, err := maurer09.NewProtocol(
		phi,
		scalarField,
		curve,
		scalarField,
		challengeActionOnPreImage,
		challengeActionOnImage,
		scalarField.Random,
		crand.Reader,
	)
	require.NoError(t, err)

	// Create witness and INCORRECT statement
	witness, err := scalarField.Random(crand.Reader)
	require.NoError(t, err)
	
	// Use a random point instead of phi(witness)
	incorrectStatement, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	w := &maurer09.Witness[*k256.Scalar]{W: witness}
	s := &maurer09.Statement[*k256.Scalar, *k256.Point]{
		X:   incorrectStatement,
		Phi: phi,
	}

	// Run protocol
	commitment, state, err := protocol.ComputeProverCommitment(s, w)
	require.NoError(t, err)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(t, err)

	response, err := protocol.ComputeProverResponse(s, w, commitment, state, challenge)
	require.NoError(t, err)

	// Verify should fail
	err = protocol.Verify(s, commitment, challenge, response)
	require.Error(t, err)
}

// TestMaurer09Protocol_Simulator tests the zero-knowledge property via simulator
func TestMaurer09Protocol_Simulator(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	basePoint, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	phi := func(s *k256.Scalar) *k256.Point {
		return basePoint.ScalarMul(s)
	}

	scalarField := curve.ScalarStructure().(algebra.PrimeField[*k256.Scalar])

	challengeActionOnPreImage := func(c *k256.Scalar, x *k256.Scalar) *k256.Scalar {
		return x.Mul(c)
	}
	challengeActionOnImage := func(c *k256.Scalar, x *k256.Point) *k256.Point {
		return x.ScalarMul(c)
	}

	protocol, err := maurer09.NewProtocol(
		phi,
		scalarField,
		curve,
		scalarField,
		challengeActionOnPreImage,
		challengeActionOnImage,
		scalarField.Random,
		crand.Reader,
	)
	require.NoError(t, err)

	// Create a random statement (without knowing witness)
	randomStatement, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	s := &maurer09.Statement[*k256.Scalar, *k256.Point]{
		X:   randomStatement,
		Phi: phi,
	}

	// Simulate
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(t, err)

	commitment, response, err := protocol.RunSimulator(s, challenge)
	require.NoError(t, err)

	// Verify simulated proof
	err = protocol.Verify(s, commitment, challenge, response)
	require.NoError(t, err)
}

// TestMaurer09Protocol_AdditiveGroup tests with additive group homomorphism
func TestMaurer09Protocol_AdditiveGroup(t *testing.T) {
	t.Parallel()

	// Use integers modulo a prime
	p := cardinal.New(101) // Small prime for testing
	zp, err := num.NewZn(p)
	require.NoError(t, err)

	// Fixed "generator" for the homomorphism
	g := zp.FromUint64(7)

	// Homomorphism: x -> g * x (additive notation)
	phi := func(x *num.Uint) *num.Uint {
		return g.Mul(x)
	}

	// Challenge actions
	challengeActionOnPreImage := func(c *num.Uint, x *num.Uint) *num.Uint {
		return x.Mul(c)
	}
	challengeActionOnImage := func(c *num.Uint, x *num.Uint) *num.Uint {
		return x.Mul(c)
	}

	// Create protocol
	protocol, err := maurer09.NewProtocol(
		phi,
		zp,
		zp,
		zp,
		challengeActionOnPreImage,
		challengeActionOnImage,
		zp.Random,
		crand.Reader,
	)
	require.NoError(t, err)

	// Create witness and statement
	witness, err := zp.Random(crand.Reader)
	require.NoError(t, err)
	statement := phi(witness)

	w := &maurer09.Witness[*num.Uint]{W: witness}
	s := &maurer09.Statement[*num.Uint, *num.Uint]{
		X:   statement,
		Phi: phi,
	}

	// Run protocol
	commitment, state, err := protocol.ComputeProverCommitment(s, w)
	require.NoError(t, err)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(t, err)

	response, err := protocol.ComputeProverResponse(s, w, commitment, state, challenge)
	require.NoError(t, err)

	// Verify
	err = protocol.Verify(s, commitment, challenge, response)
	require.NoError(t, err)
}

// TestMaurer09Protocol_BytesSerialization tests that all protocol elements can be serialized
func TestMaurer09Protocol_BytesSerialization(t *testing.T) {
	curve := k256.NewCurve()
	basePoint, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	phi := func(s *k256.Scalar) *k256.Point {
		return basePoint.ScalarMul(s)
	}

	scalarField := curve.ScalarStructure().(algebra.PrimeField[*k256.Scalar])

	// Create witness and statement
	witness, err := scalarField.Random(crand.Reader)
	require.NoError(t, err)
	statement := phi(witness)

	w := &maurer09.Witness[*k256.Scalar]{W: witness}
	s := &maurer09.Statement[*k256.Scalar, *k256.Point]{
		X:   statement,
		Phi: phi,
	}

	// Test serialization
	witnessBytes := w.Bytes()
	require.NotEmpty(t, witnessBytes)
	require.Equal(t, witness.Bytes(), witnessBytes)

	statementBytes := s.Bytes()
	require.NotEmpty(t, statementBytes)
	require.Equal(t, statement.Bytes(), statementBytes)

	// Create commitment and response
	challengeActionOnPreImage := func(c *k256.Scalar, x *k256.Scalar) *k256.Scalar {
		return x.Mul(c)
	}
	challengeActionOnImage := func(c *k256.Scalar, x *k256.Point) *k256.Point {
		return x.ScalarMul(c)
	}

	protocol, err := maurer09.NewProtocol(
		phi,
		scalarField,
		curve,
		scalarField,
		challengeActionOnPreImage,
		challengeActionOnImage,
		scalarField.Random,
		crand.Reader,
	)
	require.NoError(t, err)

	commitment, state, err := protocol.ComputeProverCommitment(s, w)
	require.NoError(t, err)

	commitmentBytes := commitment.Bytes()
	require.NotEmpty(t, commitmentBytes)

	stateBytes := state.Bytes()
	require.NotEmpty(t, stateBytes)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(crand.Reader, challenge)
	require.NoError(t, err)

	response, err := protocol.ComputeProverResponse(s, w, commitment, state, challenge)
	require.NoError(t, err)

	responseBytes := response.Bytes()
	require.NotEmpty(t, responseBytes)
}

// TestMaurer09Protocol_NilHandling tests proper error handling for nil inputs
func TestMaurer09Protocol_NilHandling(t *testing.T) {
	curve := k256.NewCurve()
	basePoint, err := curve.Random(crand.Reader)
	require.NoError(t, err)

	phi := func(s *k256.Scalar) *k256.Point {
		return basePoint.ScalarMul(s)
	}

	scalarField := curve.ScalarStructure().(algebra.PrimeField[*k256.Scalar])

	challengeActionOnPreImage := func(c *k256.Scalar, x *k256.Scalar) *k256.Scalar {
		return x.Mul(c)
	}
	challengeActionOnImage := func(c *k256.Scalar, x *k256.Point) *k256.Point {
		return x.ScalarMul(c)
	}

	// Test nil homomorphism
	_, err = maurer09.NewProtocol(
		nil,
		scalarField,
		curve,
		scalarField,
		challengeActionOnPreImage,
		challengeActionOnImage,
		scalarField.Random,
		crand.Reader,
	)
	require.Error(t, err)

	// Test nil groups
	_, err = maurer09.NewProtocol(
		phi,
		nil,
		curve,
		scalarField,
		challengeActionOnPreImage,
		challengeActionOnImage,
		scalarField.Random,
		crand.Reader,
	)
	require.Error(t, err)

	_, err = maurer09.NewProtocol(
		phi,
		scalarField,
		nil,
		scalarField,
		challengeActionOnPreImage,
		challengeActionOnImage,
		scalarField.Random,
		crand.Reader,
	)
	require.Error(t, err)

	// Test nil challenge actions
	_, err = maurer09.NewProtocol(
		phi,
		scalarField,
		curve,
		scalarField,
		nil,
		challengeActionOnImage,
		scalarField.Random,
		crand.Reader,
	)
	require.Error(t, err)

	_, err = maurer09.NewProtocol(
		phi,
		scalarField,
		curve,
		scalarField,
		challengeActionOnPreImage,
		nil,
		scalarField.Random,
		crand.Reader,
	)
	require.Error(t, err)

	// Test nil sampler
	_, err = maurer09.NewProtocol(
		phi,
		scalarField,
		curve,
		scalarField,
		challengeActionOnPreImage,
		challengeActionOnImage,
		nil,
		crand.Reader,
	)
	require.Error(t, err)

	// Test nil serialization
	var nilWitness *maurer09.Witness[*k256.Scalar]
	require.Nil(t, nilWitness.Bytes())

	var nilStatement *maurer09.Statement[*k256.Scalar, *k256.Point]
	require.Nil(t, nilStatement.Bytes())

	var nilCommitment *maurer09.Commitment[*k256.Scalar, *k256.Point]
	require.Nil(t, nilCommitment.Bytes())

	var nilState *maurer09.State[*k256.Scalar]
	require.Nil(t, nilState.Bytes())

	var nilResponse *maurer09.Response[*k256.Scalar]
	require.Nil(t, nilResponse.Bytes())
}