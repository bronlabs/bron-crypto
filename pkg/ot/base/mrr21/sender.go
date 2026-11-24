package mrr21

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

// Sender is the sender of the batched endemic OT of MRR21 Figure 3: it sends
// the key-agreement message m_S in round 1 and, in round 2, derives both
// messages of every OT from the receiver's programmed POPFs. Because the
// receiver's key-agreement message does not depend on m_S, both parties run
// their round 1 simultaneously and the protocol takes a single round trip.
type Sender[M ot.Message, G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	participant[G, S]

	state senderState[G, S]
}

// senderState holds the round counter and the secret exponent a, which must
// stay secret: it is reused across the whole batch and reveals every message.
type senderState[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	round network.Round

	a S
}

// NewSender constructs a sender for a batch of L OTs with messages of type M
// over group, in the two-party session ctx, drawing its secret exponent from
// prng. It validates its inputs through newParticipant and starts at round 1.
func NewSender[M ot.Message, G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](ctx *session.Context, group algebra.PrimeGroup[G, S], l int, prng io.Reader) (*Sender[M, G, S], error) {
	p, err := newParticipant(ctx, group, l, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create OT sender")
	}
	appendDomainSeparator[M](ctx, l)

	return &Sender[M, G, S]{
		participant: p,
		state:       senderState[G, S]{round: 1}, //nolint:exhaustruct // a is sampled in round 1
	}, nil
}

// Round1 samples the secret exponent a and returns m_S = a·G.
func (s *Sender[M, G, S]) Round1() (*SenderRound1P2P[M, G, S], error) {
	if s.state.round != 1 {
		return nil, ot.ErrRound.WithMessage("running round 1 but sender expected round %d", s.state.round)
	}

	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](s.group.ScalarStructure())
	a, err := field.Random(s.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot sample secret exponent")
	}
	if a.IsZero() {
		return nil, ot.ErrInvalidArgument.WithMessage("sampled secret exponent is zero")
	}
	ms := s.group.ScalarBaseOp(a)

	s.state.a = a
	s.participant.state.ms = ms
	s.state.round.IncrementBy(1)
	return &SenderRound1P2P[M, G, S]{Ms: ms}, nil
}

// Round2 validates the receiver's POPFs, binds the exchange to the transcript
// and derives, for every OT i and branch j, r_{i,j} = KA.key1(a, Eval(φ_i, j),
// i ‖ j). A POPF whose evaluation is the identity, which only the receiver can
// arrange, aborts the whole batch with an identifiable abort attributed to it.
func (s *Sender[M, G, S]) Round2(r1 *ReceiverRound1P2P[M, G, S]) (*ot.SenderOutput[M], error) {
	if s.state.round != 2 {
		return nil, ot.ErrRound.WithMessage("running round 2 but sender expected round %d", s.state.round)
	}
	if r1 == nil {
		return nil, ot.ErrInvalidArgument.WithMessage("round 1 message must not be nil")
	}
	if err := r1.Validate(s, s.copartyID); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid round 1 message")
	}

	s.participant.state.phi = r1.Phis
	s.updateTranscript()
	salt, err := s.deriveKeyAgreementSalt()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("round 2")
	}

	messages := make([][2]M, s.l)
	for i := range s.l {
		for c := range byte(2) {
			y, err := s.participant.state.phi[i].Eval(c)
			if err != nil {
				return nil, errs.Join(base.ErrAbort, errs.Wrap(err)).WithTag(base.IdentifiableAbortPartyIDTag, s.copartyID).WithMessage("POPF %d is malformed on branch %d", i, c)
			}
			messages[i][c], err = deriveKey[M](deriveKeyAgreementTag(i, c), s.state.a, y, salt)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot derive message %d of OT %d", c, i)
			}
		}
	}

	output, err := ot.NewSenderOutput(messages)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot build sender output")
	}
	s.state.round.IncrementBy(1)
	return output, nil
}
