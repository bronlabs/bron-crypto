package zk

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base"
	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/network"
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
}

// NewProver creates a new prover for the zero-knowledge compiled protocol.
// The sigma protocol must have soundness error at least 2^(-80) (statistical security).
// The prover will execute rounds 2 and 4 of the protocol.
func NewProver[X sigma.Statement, W sigma.Witness, A sigma.Commitment, S sigma.State, Z sigma.Response](sessionId network.SID, tape transcripts.Transcript, sigmaProtocol sigma.Protocol[X, W, A, S, Z], statement X, witness W) (*Prover[X, W, A, S, Z], error) {
	if len(sessionId) == 0 {
		return nil, ErrInvalid.WithMessage("sessionId is empty")
	}
	if sigmaProtocol == nil {
		return nil, ErrNil.WithMessage("protocol, statement or witness")
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
	dst := fmt.Sprintf("%s-%s-%x", transcriptLabel, sigmaProtocol.Name(), sessionId)
	tape.AppendDomainSeparator(dst)

	tape.AppendBytes(statementLabel, statement.Bytes())

	ck, err := hash_comm.NewKeyFromCRSBytes(sessionId, dst)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("couldn't create hash commitment key")
	}

	comm, err := hash_comm.NewScheme(ck)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("couldn't create commitment scheme")
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
		return zero, errs2.Wrap(err).WithMessage("cannot create commitment")
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
	if err := p.comm.Verifier().Verify(p.challengeCommitment, challenge, witness); err != nil {
		return zero, errs2.Wrap(err).WithMessage("invalid challenge")
	}

	response, err := p.protocol.ComputeProverResponse(p.statement, p.witness, p.commitment, p.state, sigma.ChallengeBytes(challenge))
	if err != nil {
		return zero, errs2.Wrap(err).WithMessage("cannot generate response")
	}
	transcripts.Append(p.tape, responseLabel, response)

	p.response = response
	p.round += 2
	return response, nil
}
