package sigma

import (
	"fmt"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

type Prover[X Statement, W Witness, A Commitment, S State, Z Response] struct {
	participant[X, W, A, S, Z]

	witness W
	state   S
}

func NewProver[X Statement, W Witness, A Commitment, S State, Z Response](sessionId []byte, transcript transcripts.Transcript, sigmaProtocol Protocol[X, W, A, S, Z], statement X, witness W) (*Prover[X, W, A, S, Z], error) {
	if len(sessionId) == 0 {
		return nil, errs.NewArgument("sessionId is empty")
	}
	if sigmaProtocol == nil {
		return nil, errs.NewArgument("protocol, statement or witness is nil")
	}

	if transcript == nil {
		dst := fmt.Sprintf("%s-%s", domainSeparationTag, sigmaProtocol.Name())
		transcript = hagrid.NewTranscript(dst, nil)
	}
	transcript.AppendMessages(sessionIdLabel, sessionId)
	transcript.AppendMessages(statementLabel, sigmaProtocol.SerializeStatement(statement))

	return &Prover[X, W, A, S, Z]{
		participant: participant[X, W, A, S, Z]{
			sessionId:     sessionId,
			transcript:    transcript,
			sigmaProtocol: sigmaProtocol,
			statement:     statement,
			round:         1,
		},
		witness: witness,
	}, nil
}

func (p *Prover[X, W, A, S, Z]) Round1() (A, error) {
	var zero A

	if p.round != 1 {
		return zero, errs.NewRound("r != 1 (%d)", p.round)
	}

	commitment, state, err := p.sigmaProtocol.ComputeProverCommitment(p.statement, p.witness)
	if err != nil {
		return zero, errs.WrapFailed(err, "cannot create commitment")
	}

	p.transcript.AppendMessages(commitmentLabel, p.sigmaProtocol.SerializeCommitment(commitment))
	p.commitment = commitment
	p.state = state
	p.round += 2 // prover doesn't send anything in round 2 (skip to round 3)
	return commitment, nil
}

func (p *Prover[X, W, A, S, Z]) Round3(challengeBytes []byte) (Z, error) {
	var zero Z
	p.transcript.AppendMessages(challengeLabel, challengeBytes)

	if p.round != 3 {
		return zero, errs.NewRound("r != 3 (%d)", p.round)
	}

	response, err := p.sigmaProtocol.ComputeProverResponse(p.statement, p.witness, p.commitment, p.state, challengeBytes)
	if err != nil {
		return zero, errs.WrapFailed(err, "cannot generate response")
	}
	p.transcript.AppendMessages(responseLabel, p.sigmaProtocol.SerializeResponse(response))

	p.challengeBytes = challengeBytes
	p.response = response
	p.round += 2
	return response, nil
}
