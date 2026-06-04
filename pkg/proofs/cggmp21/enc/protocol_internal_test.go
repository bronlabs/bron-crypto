//go:debug rsa1024min=0

package enc

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const (
	internalTestKeyLen    = 512
	internalTestRangeBits = 128
	internalTestSlackBits = 256
)

func TestProtocolMethodsRejectNilInputs(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	protocol, statement, witness, commitment, state, challenge := sampleInternalTestInputs(t, prng)

	_, _, err := protocol.ComputeProverCommitment(nil, witness)
	require.ErrorIs(t, err, ErrInvalidArgument)
	_, _, err = protocol.ComputeProverCommitment(statement, nil)
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.ErrorIs(t, protocol.ValidateStatement(nil, witness), ErrInvalidArgument)
	require.ErrorIs(t, protocol.ValidateStatement(statement, nil), ErrInvalidArgument)

	_, err = protocol.ComputeProverResponse(nil, witness, commitment, state, challenge)
	require.ErrorIs(t, err, ErrInvalidArgument)
	_, err = protocol.ComputeProverResponse(statement, nil, commitment, state, challenge)
	require.ErrorIs(t, err, ErrInvalidArgument)
	_, err = protocol.ComputeProverResponse(statement, witness, nil, state, challenge)
	require.ErrorIs(t, err, ErrInvalidArgument)
	_, err = protocol.ComputeProverResponse(statement, witness, commitment, nil, challenge)
	require.ErrorIs(t, err, ErrInvalidArgument)

	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)

	require.ErrorIs(t, protocol.Verify(nil, commitment, challenge, response), ErrInvalidArgument)
	require.ErrorIs(t, protocol.Verify(statement, nil, challenge, response), ErrInvalidArgument)
	require.ErrorIs(t, protocol.Verify(statement, commitment, challenge, nil), ErrInvalidArgument)

	_, _, err = protocol.RunSimulator(nil, challenge)
	require.ErrorIs(t, err, ErrInvalidArgument)
}

func TestVerifyRejectsTamperedResponse(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	protocol, statement, witness, commitment, state, challenge := sampleInternalTestInputs(t, prng)

	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)
	tamperedZ3, err := intcom.NewWitness(response.z3.Value().Add(num.Z().FromInt64(1)))
	require.NoError(t, err)
	tamperedResponse, err := NewResponse(response.z1, response.z2, tamperedZ3)
	require.NoError(t, err)

	err = protocol.Verify(statement, commitment, challenge, tamperedResponse)
	require.ErrorIs(t, err, ErrVerificationFailed)
}

func TestVerifyRejectsOutOfRangeResponse(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	protocol, statement, witness, commitment, state, challenge := sampleInternalTestInputs(t, prng)

	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)
	outOfRangeValue := num.Z().FromInt64(1).Lsh(uint(internalTestRangeBits + internalTestSlackBits))
	outOfRangeZ1, err := paillier.NewPlaintextSymmetric(outOfRangeValue, protocol.paillierKey.PlaintextGroup().Modulus())
	require.NoError(t, err)
	outOfRangeResponse, err := NewResponse(outOfRangeZ1, response.z2, response.z3)
	require.NoError(t, err)

	err = protocol.Verify(statement, commitment, challenge, outOfRangeResponse)
	require.ErrorIs(t, err, ErrVerificationFailed)
}

func sampleInternalTestInputs(
	t *testing.T,
	prng io.Reader,
) (*Protocol[*paillier.PublicKey], *Statement, *Witness, *Commitment, *State, sigma.ChallengeBytes) {
	t.Helper()

	sk, err := paillier.SampleSecretKey(internalTestKeyLen, prng)
	require.NoError(t, err)
	ringPedersenKey, err := intcom.SampleCommitmentKey(internalTestKeyLen, prng)
	require.NoError(t, err)
	protocol, err := NewProtocol(sk.Public(), ringPedersenKey, internalTestRangeBits, internalTestSlackBits, prng)
	require.NoError(t, err)

	kInt, err := randomInternalSignedBits(internalTestRangeBits, prng)
	require.NoError(t, err)
	k, err := paillier.NewPlaintextSymmetric(kInt, sk.PlaintextGroup().Modulus())
	require.NoError(t, err)
	bigK, rho, err := encryption.Encrypt(k, sk.Public(), prng)
	require.NoError(t, err)
	statement, err := NewStatement(bigK)
	require.NoError(t, err)
	witness, err := NewWitness(k, rho)
	require.NoError(t, err)
	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)

	challenge := make(sigma.ChallengeBytes, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(t, err)
	return protocol, statement, witness, commitment, state, challenge
}

func randomInternalSignedBits(bits int, prng io.Reader) (*num.Int, error) {
	outBytes := make([]byte, bits/8+1)
	if _, err := io.ReadFull(prng, outBytes); err != nil {
		return nil, err
	}
	outBytes[0] = byte(int8(outBytes[0]) >> 7)
	return num.Z().FromTwosComplementBytesBE(outBytes)
}
