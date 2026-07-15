package dec_test

import (
	"io"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/dec"
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
) (*dec.Protocol[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], *dec.Statement[*k256.Point, *k256.BaseFieldElement, *k256.Scalar], *dec.Witness) {
	t.Helper()

	secretKey, err := paillier.SampleSecretKey(testKeyBits, prng)
	require.NoError(t, err)
	n0 := secretKey.Public()

	curve := k256.NewCurve()
	xInt := num.Z().FromInt64(42)
	xScalar, err := curve.ScalarField().FromBytesBEReduce(xInt.Big().Bytes())
	require.NoError(t, err)
	xPoint := curve.ScalarBaseMul(xScalar)

	yInt := num.Z().FromInt64(-17)
	yReduced := new(big.Int).Mod(yInt.Big(), curve.ScalarField().Order().Big())
	yScalar, err := curve.ScalarField().FromBytesBEReduce(yReduced.Bytes())
	require.NoError(t, err)
	sPoint := curve.ScalarBaseMul(yScalar)
	protocol, err := dec.NewProtocol(testL, testLPrime, testEpsilon, curve.Generator(), prng)
	require.NoError(t, err)

	kPlaintext, err := paillier.NewPlaintextSymmetric(num.Z().FromInt64(123), n0.PlaintextGroup().Modulus())
	require.NoError(t, err)
	kNonce, err := n0.SampleNonce(prng)
	require.NoError(t, err)
	k, err := n0.EncryptWithNonce(kPlaintext, kNonce)
	require.NoError(t, err)

	rho, err := n0.SampleNonce(prng)
	require.NoError(t, err)
	yPlaintext, err := paillier.NewPlaintextSymmetric(yInt, n0.PlaintextGroup().Modulus())
	require.NoError(t, err)
	encY, err := n0.EncryptWithNonce(yPlaintext, rho)
	require.NoError(t, err)
	kX, err := n0.CiphertextScalarOp(k, xInt)
	require.NoError(t, err)
	kXInv, err := n0.CiphertextOpInv(kX)
	require.NoError(t, err)
	d, err := n0.CiphertextOp(encY, kXInv)
	require.NoError(t, err)

	statement, err := dec.NewStatement(n0, k, xPoint, d, sPoint)
	require.NoError(t, err)
	witness, err := dec.NewWitness(xInt, yInt, rho)
	require.NoError(t, err)
	return protocol, statement, witness
}
