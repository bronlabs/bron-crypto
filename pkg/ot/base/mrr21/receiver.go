package mrr21

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

// Receiver is the receiver of the batched endemic OT of MRR21 Figure 3: in
// round 1 it samples an exponent b_i per OT and sends the POPF φ_i programmed
// on its choice bit c_i to m_{R,i} = b_i·G; in round 2 it derives its chosen
// message r_{i,c_i} = KA.key2(b_i, m_S, i ‖ c_i) from the sender's m_S.
type Receiver[M ot.Message, G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	participant[G, S]

	state receiverState[G, S]
}

// receiverState holds the round counter, the choice bits and the secret
// exponents b_i, which must stay secret: b_i reveals the chosen message of OT i.
type receiverState[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	round network.Round

	choices ot.Choices
	b       []S
}

// NewReceiver constructs a receiver for a batch of L OTs with messages of type
// M over group, in the two-party session ctx, drawing its secret exponents from
// prng. It validates its inputs through newParticipant and starts at round 1.
func NewReceiver[M ot.Message, G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, group algebra.PrimeGroup[G, S], l int, prng io.Reader) (*Receiver[M, G, S], error) {
	p, err := newParticipant(ctx, group, l, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create OT receiver")
	}
	appendDomainSeparator[M](ctx, l)

	return &Receiver[M, G, S]{
		participant: p,
		state:       receiverState[G, S]{round: 1}, //nolint:exhaustruct // populated in round 1
	}, nil
}

// Round1 takes the L packed choice bits, samples b_i and programs φ_i on
// (c_i, b_i·G) for every OT. Programming is not constant time in c_i.
func (r *Receiver[M, G, S]) Round1(choices ot.Choices) (*ReceiverRound1P2P[M, G, S], error) {
	if r.state.round != 1 {
		return nil, ot.ErrRound.WithMessage("running round 1 but receiver expected round %d", r.state.round)
	}
	if choices.BitLen() != r.l {
		return nil, ot.ErrInvalidArgument.WithMessage("choices holds %d bits, expected %d", choices.BitLen(), r.l)
	}

	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](r.group.ScalarStructure())
	b := make([]S, r.l)
	phi := make([]*MasnyRindalPopf[G, S], r.l)
	for i := range r.l {
		ci := (choices[i/8] >> (i % 8)) & 0b1
		bi, err := field.Random(r.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot sample exponent of OT %d", i)
		}
		if bi.IsZero() {
			return nil, ot.ErrInvalidArgument.WithMessage("sampled exponent of OT %d is zero", i)
		}
		phii, err := NewMasnyRindalProgrammedPopf(ci, r.group.ScalarBaseOp(bi), r.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot program POPF %d", i)
		}
		b[i] = bi
		phi[i] = phii
	}

	r.state.choices = choices
	r.state.b = b
	r.participant.state.phi = phi
	r.state.round.IncrementBy(1)
	return &ReceiverRound1P2P[M, G, S]{Phis: phi}, nil
}

// Round2 validates m_S, binds the exchange to the transcript and derives the
// chosen message of every OT.
func (r *Receiver[M, G, S]) Round2(r1 *SenderRound1P2P[M, G, S]) (*ot.ReceiverOutput[M], error) {
	if r.state.round != 2 {
		return nil, ot.ErrRound.WithMessage("running round 2 but receiver expected round %d", r.state.round)
	}
	if r1 == nil {
		return nil, ot.ErrInvalidArgument.WithMessage("round 1 message must not be nil")
	}
	if err := r1.Validate(r, r.copartyID); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid round 1 message")
	}

	r.participant.state.ms = r1.Ms
	r.updateTranscript()
	salt, err := r.deriveKeyAgreementSalt()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("round 2")
	}

	messages := make([]M, r.l)
	for i := range r.l {
		ci := (r.state.choices[i/8] >> (i % 8)) & 0b1
		messages[i], err = deriveKey[M](deriveKeyAgreementTag(i, ci), r.state.b[i], r.participant.state.ms, salt)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot derive message of OT %d", i)
		}
	}

	output, err := ot.NewReceiverOutput(r.state.choices, messages)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot build receiver output")
	}
	r.state.round.IncrementBy(1)
	return output, nil
}
