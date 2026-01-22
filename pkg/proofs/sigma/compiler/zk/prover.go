package zk

import (
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/errs"
)

// Prover is the prover in the zero-knowledge compiled protocol.
// It participates in rounds 2 and 4 of the 5-round protocol.
type Prover[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	participant[X, W, A, S, Z]

	challengeCommitment hash_comm.Commitment
	witness             W
	state               S
}

// NewProver creates a new prover for the zero-knowledge compiled protocol.
// The sigma protocol must have soundness error at least 2^(-80) (statistical security).
// The prover will execute rounds 2 and 4 of the protocol.
func NewProver[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](sessionID network.SID, tape transcripts.Transcript, sigmaProtocol sigma.Protocol[X, W, A, S, Z], statement X, witness W) (*Prover[X, W, A, S, Z], error) {
	if utils.IsNil(witness) {
		return nil, ErrNil.WithMessage("witness")
	}
	p, err := newParticipant(sessionID, tape, sigmaProtocol, statement)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create participant")
	}
	p.round = 2 // Prover starts at round 2 (receives verifier's challenge commitment first)
	return &Prover[X, W, A, S, Z]{
		participant:         *p,
		challengeCommitment: hash_comm.Commitment{},
		witness:             witness,
		state:               *new(S),
	}, nil
}

// Round2 processes the verifier's challenge commitment and returns the prover's
// sigma protocol commitment. This is the first prover round in the 5-round protocol.
func (p *Prover[X, W, A, S, Z]) Round2(eCommitment hash_comm.Commitment) (A, error) {
	var zero A
	if p.round != 2 {
		return zero, ErrRound.WithMessage("r != 2 (%d)", p.round)
	}

	transcripts.Append(p.tape, challengeCommitmentLabel, eCommitment)

	p.challengeCommitment = eCommitment

	commitment, state, err := p.protocol.ComputeProverCommitment(p.statement, p.witness)
	if err != nil {
		return zero, errs.Wrap(err).WithMessage("cannot create commitment")
	}

	transcripts.Append(p.tape, commitmentLabel, commitment)
	p.commitment = commitment
	p.state = state
	p.round += 2
	return commitment, nil
}

// Round4 verifies the verifier's challenge commitment opening and computes the
// prover's response. Returns the sigma protocol response (z).
func (p *Prover[X, W, A, S, Z]) Round4(challenge hash_comm.Message, witness hash_comm.Witness) (Z, error) {
	var zero Z
	p.tape.AppendBytes(challengeLabel, challenge)

	if p.round != 4 {
		return zero, ErrRound.WithMessage("r != 4 (%d)", p.round)
	}
	verifier, err := p.comm.Verifier()
	if err != nil {
		return zero, errs.Wrap(err).WithMessage("cannot create verifier")
	}
	if err := verifier.Verify(p.challengeCommitment, challenge, witness); err != nil {
		return zero, errs.Wrap(err).WithMessage("invalid challenge")
	}

	response, err := p.protocol.ComputeProverResponse(p.statement, p.witness, p.commitment, p.state, sigma.ChallengeBytes(challenge))
	if err != nil {
		return zero, errs.Wrap(err).WithMessage("cannot generate response")
	}
	transcripts.Append(p.tape, responseLabel, response)

	p.response = response
	p.round += 2
	return response, nil
}
