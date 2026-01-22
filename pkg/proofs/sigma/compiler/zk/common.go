// Package zk implements a zero-knowledge compiler that transforms honest-verifier
// zero-knowledge (HVZK) sigma protocols into fully zero-knowledge interactive
// protocols using commitment schemes.
//
// The compiler adds a preliminary round where the verifier commits to the challenge
// before seeing the prover's commitment. This prevents a malicious verifier from
// choosing challenges adaptively, ensuring zero-knowledge against any verifier.
//
// The resulting protocol has 5 rounds:
//  1. Verifier commits to challenge
//  2. Prover sends commitment (a)
//  3. Verifier opens challenge commitment
//  4. Prover sends response (z)
//  5. Verifier verifies the proof
package zk

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base"
	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/pkg/errs"
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
	sessionID network.SID
	tape      transcripts.Transcript

	protocol   sigma.Protocol[X, W, A, S, Z]
	statement  X
	commitment A
	response   Z
	comm       *hash_comm.Scheme

	round uint
}

func newParticipant[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](sessionID network.SID, tape transcripts.Transcript, sigmaProtocol sigma.Protocol[X, W, A, S, Z], statement X) (*participant[X, W, A, S, Z], error) {
	if len(sessionID) == 0 {
		return nil, ErrInvalid.WithMessage("sessionID is empty")
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

	if tape == nil {
		return nil, ErrNil.WithMessage("tape")
	}
	dst := fmt.Sprintf("%s-%s-%x", transcriptLabel, sigmaProtocol.Name(), sessionID)
	tape.AppendDomainSeparator(dst)

	tape.AppendBytes(statementLabel, statement.Bytes())

	ck, err := hash_comm.NewKeyFromCRSBytes(sessionID, dst)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("couldn't create hash commitment key")
	}

	comm, err := hash_comm.NewScheme(ck)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("couldn't create commitment scheme")
	}

	return &participant[X, W, A, S, Z]{
		sessionID:  sessionID,
		tape:       tape,
		protocol:   sigmaProtocol,
		statement:  statement,
		commitment: *new(A),
		response:   *new(Z),
		comm:       comm,
		round:      1,
	}, nil
}
