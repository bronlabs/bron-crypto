package blummod_test

import (
	"io"
	"testing"

	"github.com/bronlabs/errs-go/errs"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/blummod"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
)

func TestProtocolAcceptsSampledPaillierBlumModulus(t *testing.T) {
	prng := pcg.NewRandomised()
	protocol, err := blummod.NewProtocol(prng)
	require.NoError(t, err)

	keygen, err := paillier.NewScheme().Keygen(
		paillier.WithKeyLen(paillier.MinKeyLen),
		paillier.WithPaillierBlumModulus(),
	)
	require.NoError(t, err)
	sk, pk, err := keygen.Generate(pcg.NewRandomised())
	require.NoError(t, err)
	require.Equal(t, paillier.MinKeyLen, pk.Group().N().AnnouncedLen())

	statement := &blummod.Statement{X: pk}
	witness := &blummod.Witness{W: sk}
	require.NoError(t, protocol.ValidateStatement(statement, witness))

	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(pcg.NewRandomised(), challenge)
	require.NoError(t, err)

	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)
	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)
	require.NoError(t, protocol.Verify(statement, commitment, challenge, response))
}

func TestProtocolRejectsTamperedResponse(t *testing.T) {
	t.Parallel()

	protocol, statement, witness, challenge := newFixture(t)
	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)
	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)

	response.X[0] = response.X[0].Mul(commitment.A)
	err = protocol.Verify(statement, commitment, challenge, response)
	require.ErrorIs(t, err, blummod.ErrVerificationFailed)
}

func TestProtocolFiatShamirCompilerAcceptsValidProof(t *testing.T) {
	prng := pcg.NewRandomised()
	protocol, err := blummod.NewProtocol(prng)
	require.NoError(t, err)

	keygen, err := paillier.NewScheme().Keygen(
		paillier.WithKeyLen(paillier.MinKeyLen),
		paillier.WithPaillierBlumModulus(),
	)
	require.NoError(t, err)
	sk, pk, err := keygen.Generate(pcg.NewRandomised())
	require.NoError(t, err)
	require.Equal(t, paillier.MinKeyLen, pk.Group().N().AnnouncedLen())

	statement := &blummod.Statement{X: pk}
	witness := &blummod.Witness{W: sk}
	require.NoError(t, protocol.ValidateStatement(statement, witness))

	compiler, err := fiatshamir.NewCompiler(protocol)
	require.NoError(t, err)

	const proverID = 1
	const verifierID = 2
	quorum := hashset.NewComparable[sharing.ID](proverID, verifierID).Freeze()
	ctxs := session_testutils.MakeRandomContexts(t, quorum, pcg.NewRandomised())

	prover, err := compiler.NewProver(ctxs[proverID])
	require.NoError(t, err)
	verifier, err := compiler.NewVerifier(ctxs[verifierID])
	require.NoError(t, err)

	proof, err := prover.Prove(statement, witness)
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(statement, proof))

	proverTapeData, err := ctxs[proverID].Transcript().ExtractBytes("test", base.CollisionResistanceBytesCeil)
	require.NoError(t, err)
	verifierTapeData, err := ctxs[verifierID].Transcript().ExtractBytes("test", base.CollisionResistanceBytesCeil)
	require.NoError(t, err)
	require.Equal(t, proverTapeData, verifierTapeData)
}

func TestProtocolRejectsCommitmentWithWrongJacobiSymbol(t *testing.T) {
	t.Parallel()

	protocol, statement, witness, challenge := newFixture(t)
	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)
	response, err := protocol.ComputeProverResponse(statement, witness, commitment, state, challenge)
	require.NoError(t, err)

	rsaGroup, err := znstar.NewRSAGroupOfUnknownOrder(statement.X.Group().N())
	require.NoError(t, err)
	badCommitment := &blummod.Commitment{A: rsaGroup.One()}
	err = protocol.Verify(statement, badCommitment, challenge, response)
	require.ErrorIs(t, err, blummod.ErrVerificationFailed)
}

func TestProtocolRejectsInvalidChallengeLength(t *testing.T) {
	t.Parallel()

	protocol, statement, witness, _ := newFixture(t)
	commitment, state, err := protocol.ComputeProverCommitment(statement, witness)
	require.NoError(t, err)

	_, err = protocol.ComputeProverResponse(statement, witness, commitment, state, []byte{1, 2, 3})
	require.ErrorIs(t, err, blummod.ErrInvalidArgument)

	err = protocol.Verify(statement, commitment, []byte{1, 2, 3}, &blummod.Response{})
	require.ErrorIs(t, err, blummod.ErrInvalidArgument)
}

func TestValidateStatementRejectsNonBlumFactor(t *testing.T) {
	t.Parallel()

	protocol := errs.Must1(blummod.NewProtocol(pcg.New(9, 10)))
	group := newPaillierGroup(t, 13, 11)
	sk, err := paillier.NewPrivateKey(group)
	require.NoError(t, err)
	pk, err := paillier.NewPublicKey(group.ForgetOrder())
	require.NoError(t, err)

	err = protocol.ValidateStatement(&blummod.Statement{X: pk}, &blummod.Witness{W: sk})
	require.ErrorIs(t, err, blummod.ErrValidationFailed)
}

func newFixture(t *testing.T) (*blummod.Protocol, *blummod.Statement, *blummod.Witness, sigma.ChallengeBytes) {
	t.Helper()

	protocol, err := blummod.NewProtocol(pcg.New(1, 2))
	require.NoError(t, err)

	group := newPaillierGroup(t, 19, 31)
	sk, err := paillier.NewPrivateKey(group)
	require.NoError(t, err)
	pk, err := paillier.NewPublicKey(group.ForgetOrder())
	require.NoError(t, err)

	statement := &blummod.Statement{X: pk}
	witness := &blummod.Witness{W: sk}
	challenge := make([]byte, protocol.GetChallengeBytesLength())
	_, err = io.ReadFull(pcg.New(11, 12), challenge)
	require.NoError(t, err)

	require.NoError(t, protocol.ValidateStatement(statement, witness))
	return protocol, statement, witness, challenge
}

func newPaillierGroup(t *testing.T, p, q uint64) *znstar.PaillierGroupKnownOrder {
	t.Helper()

	pp, err := num.NPlus().FromUint64(p)
	require.NoError(t, err)
	qq, err := num.NPlus().FromUint64(q)
	require.NoError(t, err)
	group, err := znstar.NewPaillierGroup(pp, qq)
	require.NoError(t, err)
	return group
}
