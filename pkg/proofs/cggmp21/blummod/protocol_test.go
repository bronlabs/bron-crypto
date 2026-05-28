//go:debug rsa1024min=0
package blummod_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/blummod"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
)

const testKeyLen = 512

func TestNonInteractiveFiatShamirHappyPath(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	sk, err := paillier.SampleBlumSecretKey(testKeyLen, prng)
	require.NoError(t, err)

	statement, err := blummod.NewStatement(sk.Public())
	require.NoError(t, err)
	witness, err := blummod.NewWitness(sk)
	require.NoError(t, err)

	proverProtocol, err := blummod.NewProtocol(prng)
	require.NoError(t, err)
	verifierProtocol, err := blummod.NewProtocol(prng)
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

	proverBytes, err := ctxs[proverID].Transcript().ExtractBytes("sigma", 32)
	require.NoError(t, err)
	verifierBytes, err := ctxs[verifierID].Transcript().ExtractBytes("sigma", 32)
	require.NoError(t, err)
	require.Equal(t, proverBytes, verifierBytes)
}

func TestConstructorsRejectNilInputs(t *testing.T) {
	t.Parallel()

	statement, err := blummod.NewStatement(nil)
	require.Error(t, err)
	require.Nil(t, statement)

	witness, err := blummod.NewWitness(nil)
	require.Error(t, err)
	require.Nil(t, witness)

	commitment, err := blummod.NewCommitment(nil)
	require.Error(t, err)
	require.Nil(t, commitment)

	state, err := blummod.NewState(nil)
	require.Error(t, err)
	require.Nil(t, state)

	item, err := blummod.NewResponseItem(nil, 0, 0, nil)
	require.Error(t, err)
	require.Nil(t, item)

	response, err := blummod.NewResponse()
	require.Error(t, err)
	require.Nil(t, response)
}

func TestCBORRoundTrip(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	sk, err := paillier.SampleBlumSecretKey(testKeyLen, prng)
	require.NoError(t, err)

	statement, err := blummod.NewStatement(sk.Public())
	require.NoError(t, err)
	witness, err := blummod.NewWitness(sk)
	require.NoError(t, err)
	protocol, err := blummod.NewProtocol(prng)
	require.NoError(t, err)

	roundTrippedStatement := ntu.CBORRoundTrip(t, statement)
	require.Equal(t, statement.Bytes(), roundTrippedStatement.Bytes())

	commitment, state, err := protocol.ComputeProverCommitment(roundTrippedStatement, witness)
	require.NoError(t, err)
	roundTrippedCommitment := ntu.CBORRoundTrip(t, commitment)
	require.Equal(t, commitment.Bytes(), roundTrippedCommitment.Bytes())
	roundTrippedState := ntu.CBORRoundTrip(t, state)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = prng.Read(challenge)
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

func TestValidateStatementRejectsMismatchedWitnessKey(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	sk, err := paillier.SampleBlumSecretKey(testKeyLen, prng)
	require.NoError(t, err)
	otherSK, err := paillier.SampleBlumSecretKey(testKeyLen, prng)
	require.NoError(t, err)

	statement, err := blummod.NewStatement(sk.Public())
	require.NoError(t, err)
	witness, err := blummod.NewWitness(otherSK)
	require.NoError(t, err)
	protocol, err := blummod.NewProtocol(prng)
	require.NoError(t, err)

	err = protocol.ValidateStatement(statement, witness)
	require.Error(t, err)
}

func TestValidateStatementAcceptsNonBlumWitnessForMatchingStatement(t *testing.T) {
	t.Parallel()

	p, err := num.NPlus().FromBig(big.NewInt(5))
	require.NoError(t, err)
	q, err := num.NPlus().FromBig(big.NewInt(7))
	require.NoError(t, err)
	group, err := znstar.NewPaillierGroup(p, q)
	require.NoError(t, err)
	sk, err := paillier.NewSecretKey(group)
	require.NoError(t, err)

	statement, err := blummod.NewStatement(sk.Public())
	require.NoError(t, err)
	witness, err := blummod.NewWitness(sk)
	require.NoError(t, err)
	protocol, err := blummod.NewProtocol(pcg.NewRandomised())
	require.NoError(t, err)

	err = protocol.ValidateStatement(statement, witness)
	require.NoError(t, err)
}
