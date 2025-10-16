package zk

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base"
	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

type Prover[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	participant[X, W, A, S, Z]

	challengeCommitment hash_comm.Commitment
	witness             W
	state               S
}

func NewProver[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](sessionId network.SID, tape transcripts.Transcript, sigmaProtocol sigma.Protocol[X, W, A, S, Z], statement X, witness W) (*Prover[X, W, A, S, Z], error) {
	if len(sessionId) == 0 {
		return nil, errs.NewArgument("sessionId is empty")
	}
	if sigmaProtocol == nil {
		return nil, errs.NewArgument("protocol, statement or witness is nil")
	}
	if s := sigmaProtocol.SoundnessError(); s < base.StatisticalSecurityBits {
		return nil, errs.NewArgument("soundness of the interactive protocol (%d) is too low (below %d)", s, base.StatisticalSecurityBits)
	}
	if sigmaProtocol.GetChallengeBytesLength() > k256Impl.FqBytes {
		return nil, errs.NewFailed("challengeBytes is too long for the compiler")
	}
	if tape == nil {
		return nil, errs.NewIsNil("tape is nil")
	}
	dst := fmt.Sprintf("%s-%s-%x", transcriptLabel, sigmaProtocol.Name(), sessionId)
	tape.AppendDomainSeparator(dst)

	ck, err := hash_comm.NewKeyFromCRSBytes(sessionId, dst)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't create hash commitment key")
	}

	comm, err := hash_comm.NewScheme(ck)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't create commitment scheme")
	}

	return &Prover[X, W, A, S, Z]{
		participant: participant[X, W, A, S, Z]{
			sessionId: sessionId,
			tape:      tape,
			protocol:  sigmaProtocol,
			statement: statement,
			comm:      comm,
			round:     2,
		},
		witness: witness,
	}, nil
}

func (p *Prover[X, W, A, S, Z]) Round2(eCommitment hash_comm.Commitment) (A, error) {
	var zero A
	if p.round != 2 {
		return zero, errs.NewRound("r != 2 (%d)", p.round)
	}

	transcripts.Append(p.tape, challengeCommitmentLabel, eCommitment)

	p.challengeCommitment = eCommitment

	commitment, state, err := p.protocol.ComputeProverCommitment(p.statement, p.witness)
	if err != nil {
		return zero, errs.WrapFailed(err, "cannot create commitment")
	}

	transcripts.Append(p.tape, commitmentLabel, commitment)
	p.commitment = commitment
	p.state = state
	p.round += 2
	return commitment, nil
}

func (p *Prover[X, W, A, S, Z]) Round4(challenge hash_comm.Message, witness hash_comm.Witness) (Z, error) {
	var zero Z
	p.tape.AppendBytes(challengeLabel, challenge)

	if p.round != 4 {
		return zero, errs.NewRound("r != 4 (%d)", p.round)
	}
	if err := p.comm.Verifier().Verify(p.challengeCommitment, challenge, witness); err != nil {
		return zero, errs.WrapVerification(err, "invalid challenge")
	}

	response, err := p.protocol.ComputeProverResponse(p.statement, p.witness, p.commitment, p.state, sigma.ChallengeBytes(challenge))
	if err != nil {
		return zero, errs.WrapFailed(err, "cannot generate response")
	}
	transcripts.Append(p.tape, responseLabel, response)

	p.response = response
	p.round += 2
	return response, nil
}
