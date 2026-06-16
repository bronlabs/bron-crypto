//go:debug rsa1024min=0
package blummod

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
)

const internalTestKeyLen = 512

func TestProtocolMethodsRejectNilInputs(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	sk, err := paillier.SampleBlumSecretKey(internalTestKeyLen, prng)
	require.NoError(t, err)
	statement, err := NewStatement(sk.Public())
	require.NoError(t, err)
	witness, err := NewWitness(sk)
	require.NoError(t, err)
	protocol, err := NewProtocol(prng)
	require.NoError(t, err)
	challenge := make([]byte, protocol.GetChallengeBytesLength())

	_, _, err = protocol.ComputeProverCommitment(nil, witness)
	require.ErrorIs(t, err, ErrInvalidArgument)
	_, _, err = protocol.ComputeProverCommitment(statement, nil)
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.ErrorIs(t, protocol.ValidateStatement(nil, witness), ErrInvalidArgument)
	require.ErrorIs(t, protocol.ValidateStatement(statement, nil), ErrInvalidArgument)

	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)

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
	sk, err := paillier.SampleBlumSecretKey(internalTestKeyLen, prng)
	require.NoError(t, err)
	statement, err := NewStatement(sk.Public())
	require.NoError(t, err)
	witness, err := NewWitness(sk)
	require.NoError(t, err)
	protocol, err := NewProtocol(prng)
	require.NoError(t, err)
	challenge := make([]byte, protocol.GetChallengeBytesLength())

	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)
	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)

	items := response.items
	tamperedItem, err := NewResponseItem(items[0].x, items[0].a^1, items[0].b, items[0].z)
	require.NoError(t, err)
	items[0] = tamperedItem
	tamperedResponse, err := NewResponse(items[:]...)
	require.NoError(t, err)

	err = protocol.Verify(statement, commitment, challenge, tamperedResponse)
	require.ErrorIs(t, err, ErrVerificationFailed)
}

func TestFiatShamirChallengeBindsCommitment(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	sk, err := paillier.SampleBlumSecretKey(internalTestKeyLen, prng)
	require.NoError(t, err)
	statement, err := NewStatement(sk.Public())
	require.NoError(t, err)
	witness, err := NewWitness(sk)
	require.NoError(t, err)
	protocol, err := NewProtocol(prng)
	require.NoError(t, err)

	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)
	otherCommitment, _, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)
	require.NotEqual(t, commitment.Bytes(), otherCommitment.Bytes())

	const proverID = 1
	const verifierID = 2
	quorum := hashset.NewComparable[sharing.ID](proverID, verifierID).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, quorum, prng)

	challenge := deriveFiatShamirChallenge(t, protocol, statement, commitment, ctxs[proverID])
	otherChallenge := deriveFiatShamirChallenge(t, protocol, statement, otherCommitment, ctxs[verifierID])
	require.NotEqual(t, challenge, otherChallenge)

	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)
	require.NoError(t, protocol.Verify(statement, commitment, challenge, response))
	require.ErrorIs(t, protocol.Verify(statement, otherCommitment, challenge, response), ErrVerificationFailed)
}

func deriveFiatShamirChallenge(
	t *testing.T,
	protocol *Protocol,
	statement *Statement,
	commitment *Commitment,
	ctx *session.Context,
) []byte {
	t.Helper()

	compiler, err := fiatshamir.NewCompiler(protocol)
	require.NoError(t, err)
	_, err = compiler.NewProver(ctx)
	require.NoError(t, err)

	ctx.Transcript().AppendBytes("statementLabel-", statement.Bytes())
	ctx.Transcript().AppendBytes("commitmentLabel-", commitment.Bytes())
	challenge, err := ctx.Transcript().ExtractBytes("challengeLabel-", uint(protocol.GetChallengeBytesLength()))
	require.NoError(t, err)
	return challenge
}
