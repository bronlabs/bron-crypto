package zk

import (
	"encoding/hex"
	"fmt"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/proofs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const (
	transcriptLabel          = "zkCompiler"
	statementLabel           = "zkCompilerStatement"
	challengeCommitmentLabel = "zkCompilerChallengeCommitment"
	commitmentLabel          = "zkCompilerCommitment"
	challengeLabel           = "zkCompilerChallenge"
	responseLabel            = "zkCompilerResponse"
	ckLabel                  = "zkCompilerCommitmentKey"
)

type participant[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	ctx *session.Context

	protocol   sigma.Protocol[X, W, A, S, Z]
	statement  X
	commitment A
	response   Z
	ck         *hashcom.CommitmentKey

	round uint
}

func newParticipant[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](ctx *session.Context, sigmaProtocol sigma.Protocol[X, W, A, S, Z], statement X) (*participant[X, W, A, S, Z], error) {
	if ctx == nil {
		return nil, proofs.ErrInvalidArgument.WithMessage("ctx is empty")
	}
	if sigmaProtocol == nil {
		return nil, proofs.ErrInvalidArgument.WithMessage("protocol is nil")
	}
	if s := sigmaProtocol.SoundnessError(); s < base.StatisticalSecurityBits {
		return nil, proofs.ErrInvalidArgument.WithMessage("soundness of the interactive protocol (%d) is too low (below %d)", s, base.StatisticalSecurityBits)
	}
	if sigmaProtocol.GetChallengeBytesLength() > k256Impl.FqBytes {
		return nil, proofs.ErrInvalidArgument.WithMessage("challengeBytes is too long for the compiler")
	}

	sessionID := ctx.SessionID()
	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, sigmaProtocol.Name(), hex.EncodeToString(sessionID[:]))
	ctx.Transcript().AppendDomainSeparator(dst)
	ctx.Transcript().AppendBytes(statementLabel, statement.Bytes())

	ck, err := hashcom.ExtractCommitmentKey(ctx.Transcript(), ckLabel)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("couldn't create hash commitment key")
	}

	return &participant[X, W, A, S, Z]{
		ctx:        ctx,
		protocol:   sigmaProtocol,
		statement:  statement,
		commitment: *new(A),
		response:   *new(Z),
		ck:         ck,
		round:      1,
	}, nil
}
