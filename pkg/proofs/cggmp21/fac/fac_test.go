//go:debug rsa1024min=0

package fac_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
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
