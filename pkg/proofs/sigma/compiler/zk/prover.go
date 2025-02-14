package zkcompiler

import (
	"fmt"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/commitments"
	hashcommitments "github.com/bronlabs/krypton-primitives/pkg/commitments/hash"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts"
)

type Prover[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	participant[X, W, A, S, Z]

	challengeCommitment hashcommitments.Commitment
	witness             W
	state               S
}

func NewProver[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](sessionId []byte, tape transcripts.Transcript, sigmaProtocol sigma.Protocol[X, W, A, S, Z], statement X, witness W) (*Prover[X, W, A, S, Z], error) {
	if len(sessionId) == 0 {
		return nil, errs.NewArgument("sessionId is empty")
	}
	if sigmaProtocol == nil {
		return nil, errs.NewArgument("protocol, statement or witness is nil")
	}
	if s := sigmaProtocol.SoundnessError(); s < base.StatisticalSecurity {
		return nil, errs.NewArgument("soundness of the interactive protocol (%d) is too low (below %d)", s, base.StatisticalSecurity)
	}

	crs, err := tape.Bind(sessionId, fmt.Sprintf("%s-%s", sigmaProtocol.Name(), transcriptLabel))
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}
	tape.AppendMessages(statementLabel, sigmaProtocol.SerializeStatement(statement))

	ck, err := hashcommitments.NewCommittingKeyFromCrsBytes(sessionId, crs)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't create committingKey")
	}

	return &Prover[X, W, A, S, Z]{
		participant: participant[X, W, A, S, Z]{
			sessionId: sessionId,
			tape:      tape,
			ck:        ck,
			protocol:  sigmaProtocol,
			statement: statement,
			round:     2,
		},
		witness: witness,
	}, nil
}

func (p *Prover[X, W, A, S, Z]) Round2(eCommitment hashcommitments.Commitment) (A, error) {
	var zero A
	if p.round != 2 {
		return zero, errs.NewRound("r != 2 (%d)", p.round)
	}

	p.tape.AppendMessages(challengeCommitmentLabel, eCommitment[:])
	p.challengeCommitment = eCommitment

	commitment, state, err := p.protocol.ComputeProverCommitment(p.statement, p.witness)
	if err != nil {
		return zero, errs.WrapFailed(err, "cannot create commitment")
	}

	p.tape.AppendMessages(commitmentLabel, p.protocol.SerializeCommitment(commitment))
	p.commitment = commitment
	p.state = state
	p.round += 2
	return commitment, nil
}

func (p *Prover[X, W, A, S, Z]) Round4(challengeOpening *commitments.Opening[hashcommitments.Message, hashcommitments.Witness]) (Z, error) {
	var zero Z
	p.tape.AppendMessages(challengeLabel, challengeOpening.Message())

	if p.round != 4 {
		return zero, errs.NewRound("r != 4 (%d)", p.round)
	}
	if err := p.ck.Verify(p.challengeCommitment, challengeOpening.Message(), challengeOpening.Witness()); err != nil {
		return zero, errs.WrapVerification(err, "invalid challenge")
	}

	response, err := p.protocol.ComputeProverResponse(p.statement, p.witness, p.commitment, p.state, sigma.ChallengeBytes(challengeOpening.Message()))
	if err != nil {
		return zero, errs.WrapFailed(err, "cannot generate response")
	}
	p.tape.AppendMessages(responseLabel, p.protocol.SerializeResponse(response))

	p.challengeBytes = sigma.ChallengeBytes(challengeOpening.Message())
	p.response = response
	p.round += 2
	return response, nil
}
