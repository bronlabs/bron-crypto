package dkg

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/errs-go/errs"
)

// Round1P2P carries round 1 peer-to-peer messages.
type Round1P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	OtR1 *vsot.Round1P2P[P, B, S] `cbor:"otR1"`
}

func (m *Round1P2P[P, B, S]) Validate(p *Participant[P, B, S], from sharing.ID) error {
	if m == nil || m.OtR1 == nil {
		return ErrNil.WithMessage("missing fields in Round1P2P message")
	}
	recv, ok := p.baseOTReceivers[from]
	if !ok {
		return ErrNil.WithMessage("missing OT receiver")
	}
	if err := m.OtR1.Validate(recv, from); err != nil {
		return errs.Wrap(err)
	}

	return nil
}

// Round2P2P carries round 2 peer-to-peer messages.
type Round2P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	OtR2 *vsot.Round2P2P[P, B, S] `cbor:"otR2"`
}

func (m *Round2P2P[P, B, S]) Validate(p *Participant[P, B, S], from sharing.ID) error {
	if m == nil || m.OtR2 == nil {
		return ErrNil.WithMessage("missing fields in Round2P2P message")
	}
	send, ok := p.baseOTSenders[from]
	if !ok {
		return ErrNil.WithMessage("missing OT sender")
	}
	if err := m.OtR2.Validate(send, from); err != nil {
		return errs.Wrap(err)
	}

	return nil
}

// Round3P2P carries round 3 peer-to-peer messages.
type Round3P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	OtR3 *vsot.Round3P2P[P, B, S] `cbor:"otR3"`
}

func (m *Round3P2P[P, B, S]) Validate(p *Participant[P, B, S], from sharing.ID) error {
	if m == nil || m.OtR3 == nil {
		return ErrNil.WithMessage("missing fields in Round3P2P message")
	}
	recv, ok := p.baseOTReceivers[from]
	if !ok {
		return ErrNil.WithMessage("missing OT receiver")
	}
	if err := m.OtR3.Validate(recv, from); err != nil {
		return errs.Wrap(err)
	}

	return nil
}

// Round4P2P carries round 4 peer-to-peer messages.
type Round4P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	OtR4 *vsot.Round4P2P[P, B, S] `cbor:"otR4"`
}

func (m *Round4P2P[P, B, S]) Validate(p *Participant[P, B, S], from sharing.ID) error {
	if m == nil || m.OtR4 == nil {
		return ErrNil.WithMessage("missing fields in Round2P2P message")
	}
	send, ok := p.baseOTSenders[from]
	if !ok {
		return ErrNil.WithMessage("missing OT sender")
	}
	if err := m.OtR4.Validate(send, from); err != nil {
		return errs.Wrap(err)
	}

	return nil
}

// Round5P2P carries round 5 peer-to-peer messages.
type Round5P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	OtR5 *vsot.Round5P2P[P, B, S] `cbor:"otR5"`
}

func (m *Round5P2P[P, B, S]) Validate(p *Participant[P, B, S], from sharing.ID) error {
	if m == nil || m.OtR5 == nil {
		return ErrNil.WithMessage("missing fields in Round1P2P message")
	}
	recv, ok := p.baseOTReceivers[from]
	if !ok {
		return ErrNil.WithMessage("missing OT receiver")
	}
	if err := m.OtR5.Validate(recv, from); err != nil {
		return errs.Wrap(err)
	}

	return nil
}
