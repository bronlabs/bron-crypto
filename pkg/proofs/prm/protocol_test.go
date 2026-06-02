//go:debug rsa1024min=0
package prm_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/prm"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
)

const testKeyLen = 64

func TestNonInteractiveFiatShamirHappyPath(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	trapdoorKey, err := intcom.SampleTrapdoorKey(testKeyLen, prng)
	require.NoError(t, err)

	statement, err := prm.NewStatement(trapdoorKey.Export())
	require.NoError(t, err)
	witness, err := prm.NewWitness(trapdoorKey)
	require.NoError(t, err)

	proverProtocol, err := prm.NewProtocol(prng)
	require.NoError(t, err)
	verifierProtocol, err := prm.NewProtocol(prng)
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

	statement, err := prm.NewStatement(nil)
	require.ErrorIs(t, err, prm.ErrInvalidArgument)
	require.Nil(t, statement)

	witness, err := prm.NewWitness(nil)
	require.ErrorIs(t, err, prm.ErrInvalidArgument)
	require.Nil(t, witness)

	commitment, err := prm.NewCommitment()
	require.ErrorIs(t, err, prm.ErrInvalidArgument)
	require.Nil(t, commitment)

	protocol, err := prm.NewProtocol(pcg.NewRandomised())
	require.NoError(t, err)
	itemCount := protocol.GetChallengeBytesLength() * 8

	commitmentItems := make([]*znstar.RSAGroupElementUnknownOrder, itemCount)
	commitment, err = prm.NewCommitment(commitmentItems...)
	require.ErrorIs(t, err, prm.ErrInvalidArgument)
	require.Nil(t, commitment)

	state, err := prm.NewState()
	require.ErrorIs(t, err, prm.ErrInvalidArgument)
	require.Nil(t, state)

	stateItems := make([]*num.Uint, itemCount)
	state, err = prm.NewState(stateItems...)
	require.ErrorIs(t, err, prm.ErrInvalidArgument)
	require.Nil(t, state)

	response, err := prm.NewResponse()
	require.ErrorIs(t, err, prm.ErrInvalidArgument)
	require.Nil(t, response)

	responseItems := make([]*num.Int, itemCount)
	response, err = prm.NewResponse(responseItems...)
	require.ErrorIs(t, err, prm.ErrInvalidArgument)
	require.Nil(t, response)
}

func TestCBORRoundTrip(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	trapdoorKey, err := intcom.SampleTrapdoorKey(testKeyLen, prng)
	require.NoError(t, err)

	statement, err := prm.NewStatement(trapdoorKey.Export())
	require.NoError(t, err)
	witness, err := prm.NewWitness(trapdoorKey)
	require.NoError(t, err)
	protocol, err := prm.NewProtocol(prng)
	require.NoError(t, err)

	roundTrippedStatement := ntu.CBORRoundTrip(t, statement)
	require.Equal(t, statement.Bytes(), roundTrippedStatement.Bytes())

	commitment, state, err := protocol.ComputeProverCommitment(roundTrippedStatement, witness)
	require.NoError(t, err)
	roundTrippedCommitment := ntu.CBORRoundTrip(t, commitment)
	require.Equal(t, commitment.Bytes(), roundTrippedCommitment.Bytes())
	roundTrippedState := ntu.CBORRoundTrip(t, state)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(t, err)
	response, err := protocol.ComputeProverResponse(
		roundTrippedStatement,
		witness,
		roundTrippedCommitment,
		roundTrippedState,
		challenge,
	)
	require.NoError(t, err)

	roundTrippedResponse := ntu.CBORRoundTrip(t, response)
	require.Equal(t, response.Bytes(), roundTrippedResponse.Bytes())
	require.NoError(t, protocol.Verify(roundTrippedStatement, roundTrippedCommitment, challenge, roundTrippedResponse))
}

func TestSimulator(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	trapdoorKey, err := intcom.SampleTrapdoorKey(testKeyLen, prng)
	require.NoError(t, err)

	statement, err := prm.NewStatement(trapdoorKey.Export())
	require.NoError(t, err)
	protocol, err := prm.NewProtocol(prng)
	require.NoError(t, err)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(t, err)

	commitment, response, err := protocol.RunSimulator(statement, challenge)
	require.NoError(t, err)
	err = protocol.Verify(statement, commitment, challenge, response)
	require.NoError(t, err)
}

func TestVerifyRejectsOutOfRangeResponse(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	trapdoorKey, err := intcom.SampleTrapdoorKey(testKeyLen, prng)
	require.NoError(t, err)

	statement, err := prm.NewStatement(trapdoorKey.Export())
	require.NoError(t, err)
	protocol, err := prm.NewProtocol(prng)
	require.NoError(t, err)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(prng, challenge)
	require.NoError(t, err)

	commitment, _, err := protocol.RunSimulator(statement, challenge)
	require.NoError(t, err)

	itemCount := protocol.GetChallengeBytesLength() * 8
	zs := make([]*num.Int, itemCount)
	zs[0] = trapdoorKey.Group().Modulus().Lift().Increment()
	for i := 1; i < len(zs); i++ {
		zs[i] = num.Z().FromInt64(0)
	}
	response, err := prm.NewResponse(zs...)
	require.NoError(t, err)

	err = protocol.Verify(statement, commitment, challenge, response)
	require.ErrorIs(t, err, prm.ErrVerificationFailed)
}

func TestValidateStatementRejectsMismatchedWitness(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	trapdoorKey, err := intcom.SampleTrapdoorKey(testKeyLen, prng)
	require.NoError(t, err)
	otherTrapdoorKey, err := intcom.SampleTrapdoorKey(testKeyLen, prng)
	require.NoError(t, err)

	statement, err := prm.NewStatement(trapdoorKey.Export())
	require.NoError(t, err)
	witness, err := prm.NewWitness(otherTrapdoorKey)
	require.NoError(t, err)
	protocol, err := prm.NewProtocol(prng)
	require.NoError(t, err)

	err = protocol.ValidateStatement(statement, witness)
	require.Error(t, err)
}
