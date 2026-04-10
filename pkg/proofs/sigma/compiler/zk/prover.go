package zk

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

// Prover is the prover in the zero-knowledge compiled protocol.
// It participates in rounds 2 and 4 of the 5-round protocol.
type Prover[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response] struct {
	participant[X, W, A, S, Z]

	challengeCommitment hash_comm.Commitment
	witness             W
	state               S
	prng                io.Reader
}

// NewProver creates a new prover for the zero-knowledge compiled protocol.
// The sigma protocol must have soundness error at least 2^(-80) (statistical security).
// The prover will execute rounds 2 and 4 of the protocol.
func NewProver[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](ctx *session.Context, sigmaProtocol sigma.Protocol[X, W, A, S, Z], statement X, witness W, prng io.Reader) (*Prover[X, W, A, S, Z], error) {
	if prng == nil {
		return nil, ErrNil.WithMessage("prng")
	}
	if utils.IsNil(witness) {
		return nil, ErrNil.WithMessage("witness")
	}
	p, err := newParticipant(ctx, sigmaProtocol, statement)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create participant")
	}
	p.round = 2 // Prover starts at round 2 (receives verifier's challenge commitment first)
	return &Prover[X, W, A, S, Z]{
		participant:         *p,
		challengeCommitment: hash_comm.Commitment{},
		witness:             witness,
		state:               *new(S),
		prng:                prng,
	}, nil
}

// Round2 processes the verifier's challenge commitment and returns the prover's
// sigma protocol commitment. This is the first prover round in the 5-round protocol.
func (p *Prover[X, W, A, S, Z]) Round2(eCommitment hash_comm.Commitment) (A, error) {
	var zero A
	if p.round != 2 {
		return zero, ErrRound.WithMessage("r != 2 (%d)", p.round)
	}

	transcripts.Append(p.ctx.Transcript(), challengeCommitmentLabel, eCommitment)

	p.challengeCommitment = eCommitment

	state, err := p.protocol.SampleProverState(p.witness, p.prng)
	if err != nil {
		return zero, errs.Wrap(err).WithMessage("cannot sample prover state")
	}

	commitment, err := p.protocol.ComputeProverCommitment(state)
	if err != nil {
		return zero, errs.Wrap(err).WithMessage("cannot create commitment")
	}

	transcripts.Append(p.ctx.Transcript(), commitmentLabel, commitment)
	p.commitment = commitment
	p.state = state
	p.round += 2
	return commitment, nil
}

// Round4 verifies the verifier's challenge commitment opening and computes the
// prover's response. Returns the sigma protocol response (z).
func (p *Prover[X, W, A, S, Z]) Round4(challenge hash_comm.Message, witness hash_comm.Witness) (Z, error) {
	var zero Z
	p.ctx.Transcript().AppendBytes(challengeLabel, challenge)

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

	response, err := p.protocol.ComputeProverResponse(p.witness, p.state, sigma.ChallengeBytes(challenge))
	if err != nil {
		return zero, errs.Wrap(err).WithMessage("cannot generate response")
	}
	transcripts.Append(p.ctx.Transcript(), responseLabel, response)

	p.response = response
	p.round += 2
	return response, nil
}
