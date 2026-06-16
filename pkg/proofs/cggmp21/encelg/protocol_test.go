package encelg_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/encelg"
)

const (
	testL       = 256
	testEpsilon = 512
	testKeyBits = 2048
)

func TestProtocolHappyPathAndSimulator(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	protocol, statement, witness := sampleProtocolStatementAndWitness(t, prng)
	require.Equal(t, base.ComputationalSecurityBytesCeil, protocol.GetChallengeBytesLength())

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
) (*encelg.Protocol[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], *encelg.Statement[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], *encelg.Witness[*k256.Point, *k256.Scalar]) {
	t.Helper()

	ringPedersenKey, err := intcom.SampleCommitmentKey(testKeyBits, prng)
	require.NoError(t, err)
	secretKey, err := paillier.SampleSecretKey(testKeyBits, prng)
	require.NoError(t, err)
	n0 := secretKey.Public()

	curve := k256.NewCurve()
	protocol, err := encelg.NewProtocol(ringPedersenKey, testL, testEpsilon, curve, prng)
	require.NoError(t, err)

	xInt := num.Z().FromInt64(42)
	xScalar, err := curve.ScalarField().FromBytesBEReduce(xInt.Big().Bytes())
	require.NoError(t, err)
	bxScalar, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)

	aSecretKey, err := elgamal.SampleSecretKey[*k256.Point, *k256.Scalar](curve, prng)
	require.NoError(t, err)
	aPublicKey := aSecretKey.Public()
	bxNonce, err := elgamal.NewNonce[*k256.Scalar](bxScalar)
	require.NoError(t, err)
	bxPlaintext, err := elgamal.NewPlaintext[*k256.Point, *k256.Scalar](curve.ScalarBaseMul(xScalar))
	require.NoError(t, err)
	bxCiphertext, err := aPublicKey.EncryptWithNonce(bxPlaintext, bxNonce)
	require.NoError(t, err)

	xPlaintext, err := paillier.NewPlaintextSymmetric(xInt, n0.PlaintextGroup().Modulus())
	require.NoError(t, err)
	rho, err := n0.SampleNonce(prng)
	require.NoError(t, err)
	c, err := n0.EncryptWithNonce(xPlaintext, rho)
	require.NoError(t, err)

	statement, err := encelg.NewStatement(n0, c, aPublicKey, bxCiphertext)
	require.NoError(t, err)
	witness, err := encelg.NewWitness(xInt, rho, aSecretKey, bxNonce)
	require.NoError(t, err)
	return protocol, statement, witness
}
