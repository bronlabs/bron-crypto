package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/errs-go/errs"
)

const Name commitments.Name = "Prime-order Pedersen commitment scheme"

func NewCommitment[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](v E) (*Commitment[E, S], error) {
	if utils.IsNil(v) {
		return nil, ErrIsNil.WithMessage("commitment value must not be nil")
	}
	// TODO: should we block OpIdentity?
	return &Commitment[E, S]{v: v}, nil
}

type Commitment[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	v E
}

type commitmentDTO[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	V E `cbor:"v"`
}

func (c *Commitment[E, S]) Value() E {
	return c.v
}

func (c *Commitment[E, S]) Equal(other *Commitment[E, S]) bool {
	if c == nil || other == nil {
		return c == other
	}
	return c.v.Equal(other.v)
}

func (c *Commitment[E, S]) HashCode() base.HashCode {
	return c.v.HashCode()
}

func (c *Commitment[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &commitmentDTO[E, S]{
		V: c.v,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal commitment to CBOR")
	}
	return out, nil
}

func (c *Commitment[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[commitmentDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal commitment from CBOR")
	}
	cc, err := NewCommitment(dto.V)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment value")
	}
	*c = *cc
	return nil
}

func NewWitness[S algebra.PrimeFieldElement[S]](v S) (*Witness[S], error) {
	if utils.IsNil(v) {
		return nil, ErrIsNil.WithMessage("witness value must not be nil")
	}
	return &Witness[S]{r: v}, nil
}

type Witness[S algebra.PrimeFieldElement[S]] struct {
	r S
}

type witnessDTO[S algebra.PrimeFieldElement[S]] struct {
	R S `cbor:"r"`
}

func (w *Witness[S]) Value() S {
	return w.r
}

func (w *Witness[S]) Equal(other *Witness[S]) bool {
	if w == nil || other == nil {
		return w == other
	}
	return w.r.Equal(other.r)
}

func (w *Witness[S]) HashCode() base.HashCode {
	return w.r.HashCode()
}

func (w *Witness[S]) MarshalCBOR() ([]byte, error) {
	dto := &witnessDTO[S]{
		R: w.r,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal witness to CBOR")
	}
	return out, nil
}

func (w *Witness[S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[witnessDTO[S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal witness from CBOR")
	}
	ww, err := NewWitness(dto.R)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid witness value")
	}
	*w = *ww
	return nil
}

func NewMessage[S algebra.PrimeFieldElement[S]](v S) (*Message[S], error) {
	if utils.IsNil(v) {
		return nil, ErrIsNil.WithMessage("message value must not be nil")
	}
	return &Message[S]{m: v}, nil
}

type Message[S algebra.PrimeFieldElement[S]] struct {
	m S
}

type messageDTO[S algebra.PrimeFieldElement[S]] struct {
	M S `cbor:"m"`
}

func (m *Message[S]) Value() S {
	return m.m
}

func (m *Message[S]) Equal(other *Message[S]) bool {
	if m == nil || other == nil {
		return m == other
	}
	return m.m.Equal(other.m)
}

func (m *Message[S]) HashCode() base.HashCode {
	return m.m.HashCode()
}

func (m *Message[S]) MarshalCBOR() ([]byte, error) {
	dto := &messageDTO[S]{
		M: m.m,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal message to CBOR")
	}
	return out, nil
}

func (m *Message[S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[messageDTO[S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal message from CBOR")
	}
	mm, err := NewMessage(dto.M)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid message value")
	}
	*m = *mm
	return nil
}
