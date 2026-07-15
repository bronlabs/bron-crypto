//go:debug rsa1024min=0
package prm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
)

const internalTestKeyLen = 64

func TestComputeProverResponseUsesNonNegativeRepresentatives(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	trapdoorKey, err := intcom.SampleTrapdoorKey(internalTestKeyLen, prng)
	require.NoError(t, err)

	statement, err := NewStatement(trapdoorKey.Export())
	require.NoError(t, err)
	witness, err := NewWitness(trapdoorKey)
	require.NoError(t, err)
	protocol, err := NewProtocol(prng)
	require.NoError(t, err)

	phi, err := phiFromGroup(trapdoorKey.Group())
	require.NoError(t, err)
	zPhi, err := num.NewZMod(phi)
	require.NoError(t, err)
	alpha := zPhi.Top()
	orderedT, err := trapdoorKey.T().LearnOrder(trapdoorKey.Group())
	require.NoError(t, err)

	commitmentItems := make([]*znstar.RSAGroupElementUnknownOrder, m)
	stateItems := make([]*num.Uint, m)
	for i := range stateItems {
		commitmentItems[i] = orderedT.Exp(alpha.Nat()).ForgetOrder()
		stateItems[i] = alpha
	}
	commitment, err := NewCommitment(commitmentItems...)
	require.NoError(t, err)
	state, err := NewState(stateItems...)
	require.NoError(t, err)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)
	require.NoError(t, protocol.Verify(statement, commitment, challenge, response))
	for _, z := range &response.z {
		require.False(t, z.IsNegative())
	}
}

func TestRunSimulatorUsesNonNegativeRepresentatives(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	trapdoorKey, err := intcom.SampleTrapdoorKey(internalTestKeyLen, prng)
	require.NoError(t, err)

	statement, err := NewStatement(trapdoorKey.Export())
	require.NoError(t, err)
	protocol, err := NewProtocol(prng)
	require.NoError(t, err)

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	commitment, response, err := protocol.RunSimulator(statement, challenge)
	require.NoError(t, err)
	require.NoError(t, protocol.Verify(statement, commitment, challenge, response))
	for _, z := range &response.z {
		require.False(t, z.IsNegative())
	}
}

func TestProtocolMethodsRejectNilInputs(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	trapdoorKey, err := intcom.SampleTrapdoorKey(internalTestKeyLen, prng)
	require.NoError(t, err)
	statement, err := NewStatement(trapdoorKey.Export())
	require.NoError(t, err)
	witness, err := NewWitness(trapdoorKey)
	require.NoError(t, err)
	protocol, err := NewProtocol(prng)
	require.NoError(t, err)
	challenge := make([]byte, protocol.GetChallengeBytesLength())

	_, _, err = protocol.ComputeProverCommitment(nil, witness)
	require.ErrorIs(t, err, proofs.ErrInvalidArgument)
	_, _, err = protocol.ComputeProverCommitment(statement, nil)
	require.ErrorIs(t, err, proofs.ErrInvalidArgument)
	require.ErrorIs(t, protocol.ValidateStatement(nil, witness), proofs.ErrInvalidArgument)
	require.ErrorIs(t, protocol.ValidateStatement(statement, nil), proofs.ErrInvalidArgument)

	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)

	_, err = protocol.ComputeProverResponse(statement, witness, nil, state, challenge)
	require.ErrorIs(t, err, proofs.ErrInvalidArgument)
	_, err = protocol.ComputeProverResponse(statement, witness, commitment, nil, challenge)
	require.ErrorIs(t, err, proofs.ErrInvalidArgument)

	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)

	require.ErrorIs(t, protocol.Verify(nil, commitment, challenge, response), proofs.ErrInvalidArgument)
	require.ErrorIs(t, protocol.Verify(statement, nil, challenge, response), proofs.ErrInvalidArgument)
	require.ErrorIs(t, protocol.Verify(statement, commitment, challenge, nil), proofs.ErrInvalidArgument)

	_, _, err = protocol.RunSimulator(nil, challenge)
	require.ErrorIs(t, err, proofs.ErrInvalidArgument)
}
