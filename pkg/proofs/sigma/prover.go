package sigma

import (
	"encoding/hex"
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/pkg/errs"
)

// Prover implements the interactive sigma prover.
type Prover[X Statement, W Witness, A Commitment, S State, Z Response] struct {
	participant[X, W, A, S, Z]

	witness W
	state   S
}

// NewProver constructs a sigma protocol prover.
func NewProver[X Statement, W Witness, A Commitment, S State, Z Response](sessionID network.SID, transcript transcripts.Transcript, sigmaProtocol Protocol[X, W, A, S, Z], statement X, witness W) (*Prover[X, W, A, S, Z], error) {
	if sigmaProtocol == nil {
		return nil, ErrInvalidArgument.WithMessage("protocol, statement or witness is nil")
	}
	if s := sigmaProtocol.SoundnessError(); s < base.StatisticalSecurityBits {
		return nil, ErrInvalidArgument.WithMessage("soundness of the interactive protocol (%d) is too low (below %d)", s, base.StatisticalSecurityBits)
	}

	dst := fmt.Sprintf("%s-%s-%s", hex.EncodeToString(sessionID[:]), transcriptLabel, sigmaProtocol.Name())
	transcript.AppendDomainSeparator(dst)
	transcript.AppendBytes(statementLabel, statement.Bytes())

	//nolint:exhaustruct // initial state
	return &Prover[X, W, A, S, Z]{
		//nolint:exhaustruct // initial state
		participant: participant[X, W, A, S, Z]{
			sessionID:     sessionID,
			transcript:    transcript,
			sigmaProtocol: sigmaProtocol,
			statement:     statement,
			round:         1,
		},
		witness: witness,
	}, nil
}

// Round1 runs the prover's first round.
func (p *Prover[X, W, A, S, Z]) Round1() (A, error) {
	var zero A

	if p.round != 1 {
		return zero, ErrRound.WithMessage("r != 1 (%d)", p.round)
	}

	commitment, state, err := p.sigmaProtocol.ComputeProverCommitment(p.statement, p.witness)
	if err != nil {
		return zero, errs.Wrap(err).WithMessage("cannot create commitment")
	}

	p.transcript.AppendBytes(commitmentLabel, commitment.Bytes())
	p.commitment = commitment
	p.state = state
	p.round += 2 // prover doesn't send anything in round 2 (skip to round 3)
	return commitment, nil
}

// Round3 runs the prover's third round.
func (p *Prover[X, W, A, S, Z]) Round3(challengeBytes []byte) (Z, error) {
	var zero Z
	p.transcript.AppendBytes(challengeLabel, challengeBytes)

	if p.round != 3 {
		return zero, ErrRound.WithMessage("r != 3 (%d)", p.round)
	}

	response, err := p.sigmaProtocol.ComputeProverResponse(p.statement, p.witness, p.commitment, p.state, challengeBytes)
	if err != nil {
		return zero, errs.Wrap(err).WithMessage("cannot generate response")
	}
	p.transcript.AppendBytes(responseLabel, response.Bytes())

	p.challengeBytes = challengeBytes
	p.response = response
	p.round += 2
	return response, nil
}
