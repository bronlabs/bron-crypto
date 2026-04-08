package canetti

import (
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const (
	statementLabel  = "BRON_CRYPTO_DKG_CANETTI_ZK_STATEMENT-"
	commitmentLabel = "BRON_CRYPTO_DKG_CANETTI_ZK_COMMITMENT-"
	challengeLabel  = "BRON_CRYPTO_DKG_CANETTI_ZK_CHALLENGE-"
	responseLabel   = "BRON_CRYPTO_DKG_CANETTI_ZK_RESPONSE-"
)

type ZKResponse[A sigma.Commitment, Z sigma.Response] struct {
	A A
	E sigma.ChallengeBytes
	Z Z
}

func zkCom[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](protocol sigma.Protocol[X, W, A, S, Z], statement X, witness W) (commitment A, state S, err error) {
	var nilA A
	var nilS S
	if protocol == nil {
		return nilA, nilS, ErrInvalidArgument.WithMessage("protocol is nil")
	}

	a, s, err := protocol.ComputeProverCommitment(statement, witness)
	if err != nil {
		return nilA, nilS, errs.Wrap(err).WithMessage("cannot commit")
	}
	return a, s, nil
}

func zkProve[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](ctx *session.Context, protocol sigma.Protocol[X, W, A, S, Z], statement X, witness W, commitment A, state S) (*ZKResponse[A, Z], error) {
	if ctx == nil || protocol == nil {
		return nil, ErrInvalidArgument.WithMessage("ctx/protocol is nil")
	}

	ctx.Transcript().AppendBytes(statementLabel, statement.Bytes())
	ctx.Transcript().AppendBytes(commitmentLabel, commitment.Bytes())
	e, err := ctx.Transcript().ExtractBytes(challengeLabel, uint(protocol.GetChallengeBytesLength()))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot sample challenge")
	}

	z, err := protocol.ComputeProverResponse(statement, witness, commitment, state, e)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot prove")
	}
	ctx.Transcript().AppendBytes(responseLabel, z.Bytes())

	psi := &ZKResponse[A, Z]{
		A: commitment,
		E: e,
		Z: z,
	}
	return psi, nil
}

func zkVrfy[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](ctx *session.Context, protocol sigma.Protocol[X, W, A, S, Z], statement X, response *ZKResponse[A, Z]) error {
	if ctx == nil || protocol == nil || response == nil {
		return ErrInvalidArgument.WithMessage("ctx/protocol/response is nil")
	}

	ctx.Transcript().AppendBytes(statementLabel, statement.Bytes())
	ctx.Transcript().AppendBytes(commitmentLabel, response.A.Bytes())
	ePrime, err := ctx.Transcript().ExtractBytes(challengeLabel, uint(protocol.GetChallengeBytesLength()))
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot sample challenge")
	}
	if !slices.Equal(ePrime, response.E) {
		return ErrVerificationFailed.WithMessage("invalid proof")
	}
	if err := protocol.Verify(statement, response.A, ePrime, response.Z); err != nil {
		return ErrVerificationFailed.WithMessage("invalid proof")
	}
	ctx.Transcript().AppendBytes(responseLabel, response.Z.Bytes())

	return nil
}
