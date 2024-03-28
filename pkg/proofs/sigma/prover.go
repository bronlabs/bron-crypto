package sigma

import (
	"fmt"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type Prover[X Statement, W Witness, A Commitment, S State, Z Response] struct {
	participant[X, W, A, S, Z]

	witness W
	state   S
}

func NewProver[X Statement, W Witness, A Commitment, S State, Z Response](baseParticipant types.Participant[Protocol[X, W, A, S, Z]], statement X, witness W) (*Prover[X, W, A, S, Z], error) {
	prover := &Prover[X, W, A, S, Z]{
		participant: participant[X, W, A, S, Z]{
			Participant: baseParticipant,
			statement:   statement,
		},
		witness: witness,
	}
	if err := prover.Validate(); err != nil {
		return nil, errs.WrapValidation(err, "couldn't validate %s prover", prover.Protocol().Name())
	}
	dst := fmt.Sprintf("%s-%s", transcriptLabel, prover.Protocol().Name())
	if err := prover.Initialise(1, dst); err != nil {
		return nil, errs.WrapFailed(err, "couldn't initialise prover")
	}
	prover.Transcript().AppendMessages(statementLabel, prover.Protocol().SerializeStatement(statement))
	return prover, nil
}

func (p *Prover[X, W, A, S, Z]) Round1() (A, error) {
	var zero A

	if p.Round() != 1 {
		return zero, errs.NewRound("r != 1 (%d)", p.Round())
	}

	commitment, state, err := p.Protocol().ComputeProverCommitment(p.statement, p.witness)
	if err != nil {
		return zero, errs.WrapFailed(err, "cannot create commitment")
	}

	p.Transcript().AppendMessages(commitmentLabel, p.Protocol().SerializeCommitment(commitment))
	p.commitment = commitment
	p.state = state
	p.NextRound(3) // prover doesn't send anything in round 2 (skip to round 3)
	return commitment, nil
}

func (p *Prover[X, W, A, S, Z]) Round3(challengeBytes []byte) (Z, error) {
	var zero Z
	p.Transcript().AppendMessages(challengeLabel, challengeBytes)
	if p.Round() != 3 {
		return zero, errs.NewRound("r != 3 (%d)", p.Round())
	}

	response, err := p.Protocol().ComputeProverResponse(p.statement, p.witness, p.commitment, p.state, challengeBytes)
	if err != nil {
		return zero, errs.WrapFailed(err, "cannot generate response")
	}
	p.Transcript().AppendMessages(responseLabel, p.Protocol().SerializeResponse(response))

	p.challengeBytes = challengeBytes
	p.response = response
	p.Terminate()
	return response, nil
}
