package affgstar_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/affgstar"
)

const (
	testL       = 256
	testLPrime  = 1280
	testEpsilon = 512
	testKeyBits = 2048
)

func TestProtocolHappyPathAndSimulator(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	protocol, statement, witness := sampleProtocolStatementAndWitness(t, prng)
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err := io.ReadFull(prng, challenge)
	require.NoError(t, err)

	require.NoError(t, protocol.ValidateStatement(statement, witness))

	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)
	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)
	require.NoError(t, protocol.Verify(statement, commitment, challenge, response))

	roundTrippedStatement := ntu.CBORRoundTrip(t, statement)
	require.Equal(t, statement.Bytes(), roundTrippedStatement.Bytes())
	roundTrippedCommitment := ntu.CBORRoundTrip(t, commitment)
	require.Equal(t, commitment.Bytes(), roundTrippedCommitment.Bytes())
	roundTrippedResponse := ntu.CBORRoundTrip(t, response)
	require.Equal(t, response.Bytes(), roundTrippedResponse.Bytes())
	require.NoError(t, protocol.Verify(roundTrippedStatement, roundTrippedCommitment, challenge, roundTrippedResponse))

	simulatedCommitment, simulatedResponse, err := protocol.RunSimulator(statement, challenge)
	require.NoError(t, err)
	require.NoError(t, protocol.Verify(statement, simulatedCommitment, challenge, simulatedResponse))
}

func sampleProtocolStatementAndWitness(
	t *testing.T,
	prng io.Reader,
) (*affgstar.Protocol[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], *affgstar.Statement[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], *affgstar.Witness) {
	t.Helper()

	n0SecretKey, err := paillier.SampleSecretKey(testKeyBits, prng)
	require.NoError(t, err)
	n1SecretKey, err := paillier.SampleSecretKey(testKeyBits, prng)
	require.NoError(t, err)
	n0 := n0SecretKey.Public()
	n1 := n1SecretKey.Public()

	curve := k256.NewCurve()
	protocol, err := affgstar.NewProtocol(testL, testLPrime, testEpsilon, curve, prng)
	require.NoError(t, err)

	xInt := num.Z().FromInt64(42)
	xScalar, err := curve.ScalarField().FromBytesBEReduce(xInt.Big().Bytes())
	require.NoError(t, err)
	xPoint := curve.ScalarBaseMul(xScalar)

	yInt := num.Z().FromInt64(-17)
	yN1, err := paillier.NewPlaintextSymmetric(yInt, n1.PlaintextGroup().Modulus())
	require.NoError(t, err)
	rhoY, err := n1.SampleNonce(prng)
	require.NoError(t, err)
	yCiphertext, err := n1.EncryptWithNonce(yN1, rhoY)
	require.NoError(t, err)

	cPlaintext, err := paillier.NewPlaintextSymmetric(num.Z().FromInt64(123), n0.PlaintextGroup().Modulus())
	require.NoError(t, err)
	cNonce, err := n0.SampleNonce(prng)
	require.NoError(t, err)
	c, err := n0.EncryptWithNonce(cPlaintext, cNonce)
	require.NoError(t, err)

	rho, err := n0.SampleNonce(prng)
	require.NoError(t, err)
	yN0, err := paillier.NewPlaintextSymmetric(yInt, n0.PlaintextGroup().Modulus())
	require.NoError(t, err)
	encryptedY, err := n0.EncryptWithNonce(yN0, rho)
	require.NoError(t, err)
	cX, err := n0.CiphertextScalarOp(c, xInt)
	require.NoError(t, err)
	d, err := n0.CiphertextOp(cX, encryptedY)
	require.NoError(t, err)

	statement, err := affgstar.NewStatement(n0, n1, c, d, yCiphertext, xPoint)
	require.NoError(t, err)
	witness, err := affgstar.NewWitness(xInt, yN1, rho, rhoY)
	require.NoError(t, err)
	return protocol, statement, witness
}
