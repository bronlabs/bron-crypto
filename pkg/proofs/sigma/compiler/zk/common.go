package zk

import (
	"encoding/hex"
	"fmt"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
)

const (
	transcriptLabel          = "zkCompiler"
	statementLabel           = "zkCompilerStatement"
	challengeCommitmentLabel = "zkCompilerChallengeCommitment"
	commitmentLabel          = "zkCompilerCommitment"
	challengeLabel           = "zkCompilerChallenge"
	responseLabel            = "zkCompilerResponse"
)

// CommitmentScheme is the type alias for the hash-based commitment scheme used
// to commit to verifier challenges.
type CommitmentScheme commitments.Scheme[hash_comm.Key, hash_comm.Witness, hash_comm.Message, hash_comm.Commitment, *hash_comm.Committer, *hash_comm.Verifier]

type participant[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	ctx *session.Context

	protocol   sigma.Protocol[X, W, A, S, Z]
	statement  X
	commitment A
	response   Z
	comm       *hash_comm.Scheme

	round uint
}

func newParticipant[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](ctx *session.Context, sigmaProtocol sigma.Protocol[X, W, A, S, Z], statement X) (*participant[X, W, A, S, Z], error) {
	if ctx == nil {
		return nil, ErrInvalid.WithMessage("ctx is empty")
	}
	if sigmaProtocol == nil {
		return nil, ErrNil.WithMessage("protocol")
	}
	if s := sigmaProtocol.SoundnessError(); s < base.StatisticalSecurityBits {
		return nil, ErrInvalid.WithMessage("soundness of the interactive protocol (%d) is too low (below %d)", s, base.StatisticalSecurityBits)
	}
	if sigmaProtocol.GetChallengeBytesLength() > k256Impl.FqBytes {
		return nil, ErrFailed.WithMessage("challengeBytes is too long for the compiler")
	}

	sessionID := ctx.SessionID()
	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, sigmaProtocol.Name(), hex.EncodeToString(sessionID[:]))
	ctx.Transcript().AppendDomainSeparator(dst)

	ctx.Transcript().AppendBytes(statementLabel, statement.Bytes())

	ck, err := hash_comm.NewKeyFromCRSBytes(sessionID, dst)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("couldn't create hash commitment key")
	}

	comm, err := hash_comm.NewScheme(ck)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("couldn't create commitment scheme")
	}

	return &participant[X, W, A, S, Z]{
		ctx:        ctx,
		protocol:   sigmaProtocol,
		statement:  statement,
		commitment: *new(A),
		response:   *new(Z),
		comm:       comm,
		round:      1,
	}, nil
}
