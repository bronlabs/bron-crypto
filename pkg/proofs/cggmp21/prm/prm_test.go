//go:debug rsa1024min=0
package prm_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/prm"
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

	commitment, response, err := protocol.RunSimulator(statement, challenge)
	require.NoError(t, err)
	response.Z[0] = statement.CommitmentKey.Group().Modulus().Lift().Increment()

	err = protocol.Verify(statement, commitment, challenge, response)
	require.Error(t, err)
}

func TestBytesToleratesMalformedPublicStructs(t *testing.T) {
	t.Parallel()

	require.NotPanics(t, func() {
		require.Nil(t, (&prm.Statement{CommitmentKey: &intcom.CommitmentKey{}}).Bytes())
	})
	require.NotPanics(t, func() {
		require.Nil(t, (&prm.Witness{TrapdoorKey: &intcom.TrapdoorKey{}}).Bytes())
	})
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
