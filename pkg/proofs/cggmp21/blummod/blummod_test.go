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
