//go:debug rsa1024min=0

package fac_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/fac"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
)

const (
	testRangeBits       = 128
	testSlackBits       = 256
	testPaillierKeyBits = 1024 + 512
	testSetupKeyBits    = 1024 + 512
)

func TestNonInteractiveFiatShamirHappyPath(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	setupKey, statement, witness := sampleSetupStatementAndWitness(t, prng)

	proverProtocol, err := fac.NewProtocol(setupKey, testRangeBits, testSlackBits, prng)
	require.NoError(t, err)
	verifierProtocol, err := fac.NewProtocol(setupKey, testRangeBits, testSlackBits, prng)
	require.NoError(t, err)

	err = proverProtocol.ValidateStatement(statement, witness)
	require.NoError(t, err)

	proverCompiler, err := fiatshamir.NewCompiler(proverProtocol)
	require.NoError(t, err)
	verifierCompiler, err := fiatshamir.NewCompiler(verifierProtocol)
	require.NoError(t, err)

	const proverID = 1
	const verifierID = 2
	quorum := hashset.NewComparable[sharing.ID](proverID, verifierID).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	prover, err := proverCompiler.NewProver(ctxs[proverID])
	require.NoError(t, err)
	proof, err := prover.Prove(statement, witness)
	require.NoError(t, err)

	verifier, err := verifierCompiler.NewVerifier(ctxs[verifierID])
	require.NoError(t, err)
	err = verifier.Verify(statement, proof)
	require.NoError(t, err)
}

func TestConstructorsRejectInvalidInputs(t *testing.T) {
	t.Parallel()

	statement, err := fac.NewStatement(nil)
	require.ErrorIs(t, err, fac.ErrInvalidArgument)
	require.Nil(t, statement)

	witness, err := fac.NewWitness(nil)
	require.ErrorIs(t, err, fac.ErrInvalidArgument)
	require.Nil(t, witness)

	commitment, err := fac.NewCommitment(nil, nil, nil, nil, nil)
	require.ErrorIs(t, err, fac.ErrInvalidArgument)
	require.Nil(t, commitment)

	state, err := fac.NewState(nil, nil, nil, nil, nil, nil, nil)
	require.ErrorIs(t, err, fac.ErrInvalidArgument)
	require.Nil(t, state)

	response, err := fac.NewResponse(nil, nil, nil, nil, nil)
	require.ErrorIs(t, err, fac.ErrInvalidArgument)
	require.Nil(t, response)
}

func TestProtocolMethodsRejectNilInputs(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	setupKey, statement, witness := sampleSetupStatementAndWitness(t, prng)
	protocol, err := fac.NewProtocol(setupKey, testRangeBits, testSlackBits, prng)
	require.NoError(t, err)
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(t, err)

	_, _, err = protocol.ComputeProverCommitment(nil, witness)
	require.ErrorIs(t, err, fac.ErrInvalidArgument)
	_, _, err = protocol.ComputeProverCommitment(statement, nil)
	require.ErrorIs(t, err, fac.ErrInvalidArgument)
	require.ErrorIs(t, protocol.ValidateStatement(nil, witness), fac.ErrInvalidArgument)
	require.ErrorIs(t, protocol.ValidateStatement(statement, nil), fac.ErrInvalidArgument)

	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)

	_, err = protocol.ComputeProverResponse(nil, witness, commitment, state, challenge)
	require.ErrorIs(t, err, fac.ErrInvalidArgument)
	_, err = protocol.ComputeProverResponse(statement, nil, commitment, state, challenge)
	require.ErrorIs(t, err, fac.ErrInvalidArgument)
	_, err = protocol.ComputeProverResponse(statement, witness, nil, state, challenge)
	require.ErrorIs(t, err, fac.ErrInvalidArgument)
	_, err = protocol.ComputeProverResponse(statement, witness, commitment, nil, challenge)
	require.ErrorIs(t, err, fac.ErrInvalidArgument)

	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)

	require.ErrorIs(t, protocol.Verify(nil, commitment, challenge, response), fac.ErrInvalidArgument)
	require.ErrorIs(t, protocol.Verify(statement, nil, challenge, response), fac.ErrInvalidArgument)
	require.ErrorIs(t, protocol.Verify(statement, commitment, challenge, nil), fac.ErrInvalidArgument)

	_, _, err = protocol.RunSimulator(nil, challenge)
	require.ErrorIs(t, err, fac.ErrInvalidArgument)
}

func TestCBORRoundTrip(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	setupKey, statement, witness := sampleSetupStatementAndWitness(t, prng)
	protocol, err := fac.NewProtocol(setupKey, testRangeBits, testSlackBits, prng)
	require.NoError(t, err)

	roundTrippedStatement := ntu.CBORRoundTrip(t, statement)
	require.Equal(t, statement.Bytes(), roundTrippedStatement.Bytes())

	commitment, state, err := protocol.ComputeProverCommitment(roundTrippedStatement, witness)
	require.NoError(t, err)
	roundTrippedCommitment := ntu.CBORRoundTrip(t, commitment)
	require.Equal(t, commitment.Bytes(), roundTrippedCommitment.Bytes())

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(t, err)
	response, err := protocol.ComputeProverResponse(
		roundTrippedStatement,
		witness,
		roundTrippedCommitment,
		state,
		challenge,
	)
	require.NoError(t, err)

	roundTrippedResponse := ntu.CBORRoundTrip(t, response)
	require.Equal(t, response.Bytes(), roundTrippedResponse.Bytes())
	require.NoError(t, protocol.Verify(roundTrippedStatement, roundTrippedCommitment, challenge, roundTrippedResponse))
}

func TestVerifyRejectsOutOfRangeResponse(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	setupKey, statement, _ := sampleSetupStatementAndWitness(t, prng)
	protocol, err := fac.NewProtocol(setupKey, testRangeBits, testSlackBits, prng)
	require.NoError(t, err)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(t, err)

	commitment, _, err := protocol.RunSimulator(statement, challenge)
	require.NoError(t, err)
	response, err := fac.NewResponse(
		num.Z().FromInt64(1).Lsh(uint(testPaillierKeyBits+testRangeBits+testSlackBits)),
		num.Z().Zero(),
		num.Z().Zero(),
		num.Z().Zero(),
		num.Z().Zero(),
	)
	require.NoError(t, err)

	err = protocol.Verify(statement, commitment, challenge, response)
	require.ErrorIs(t, err, fac.ErrVerificationFailed)
}

func TestVerifyRejectsOversizedRandomnessResponses(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	setupKey, statement, _ := sampleSetupStatementAndWitness(t, prng)
	protocol, err := fac.NewProtocol(setupKey, testRangeBits, testSlackBits, prng)
	require.NoError(t, err)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(t, err)

	commitment, _, err := protocol.RunSimulator(statement, challenge)
	require.NoError(t, err)
	zero := num.Z().Zero()
	oversizedW := num.Z().FromInt64(1).Lsh(uint(testSetupKeyBits + testRangeBits + testSlackBits + 1))
	oversizedV := num.Z().FromInt64(1).Lsh(uint(testPaillierKeyBits + testSetupKeyBits + testRangeBits + testSlackBits + 1))

	for _, tc := range []struct {
		name string
		w1   *num.Int
		w2   *num.Int
		v    *num.Int
	}{
		{name: "w1", w1: oversizedW, w2: zero, v: zero},
		{name: "w2", w1: zero, w2: oversizedW, v: zero},
		{name: "v", w1: zero, w2: zero, v: oversizedV},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			response, err := fac.NewResponse(zero, zero, tc.w1, tc.w2, tc.v)
			require.NoError(t, err)

			err = protocol.Verify(statement, commitment, challenge, response)
			require.ErrorIs(t, err, fac.ErrVerificationFailed)
		})
	}
}

func TestSimulator(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	setupKey, statement, _ := sampleSetupStatementAndWitness(t, prng)
	protocol, err := fac.NewProtocol(setupKey, testRangeBits, testSlackBits, prng)
	require.NoError(t, err)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(t, err)

	commitment, response, err := protocol.RunSimulator(statement, challenge)
	require.NoError(t, err)
	err = protocol.Verify(statement, commitment, challenge, response)
	require.NoError(t, err)
}

func TestValidateStatementRejectsMismatchedFactors(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	setupKey, statement, _ := sampleSetupStatementAndWitness(t, prng)
	otherSecretKey, err := paillier.SampleSecretKey(testPaillierKeyBits, prng)
	require.NoError(t, err)
	wrongWitness, err := fac.NewWitness(otherSecretKey)
	require.NoError(t, err)
	protocol, err := fac.NewProtocol(setupKey, testRangeBits, testSlackBits, prng)
	require.NoError(t, err)

	err = protocol.ValidateStatement(statement, wrongWitness)
	require.Error(t, err)
}

func sampleSetupStatementAndWitness(t *testing.T, prng io.Reader) (*intcom.CommitmentKey, *fac.Statement, *fac.Witness) {
	t.Helper()

	setupTrapdoorKey, err := intcom.SampleTrapdoorKey(testSetupKeyBits, prng)
	require.NoError(t, err)
	secretKey, err := paillier.SampleSecretKey(testPaillierKeyBits, prng)
	require.NoError(t, err)

	statement, err := fac.NewStatement(secretKey.Public())
	require.NoError(t, err)
	witness, err := fac.NewWitness(secretKey)
	require.NoError(t, err)
	return setupTrapdoorKey.Export(), statement, witness
}
