package indcpacom

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
)

func NewCommitment[C encryption.Ciphertext[C]](c C) (*Commitment[C], error) {
	if utils.IsNil(c) {
		return nil, commitments.ErrIsNil.WithMessage("ciphertext must not be nil")
	}
	return &Commitment[C]{c: c}, nil
}

type Commitment[C encryption.Ciphertext[C]] struct {
	c C
}

type commitmentDTO[C encryption.Ciphertext[C]] struct {
	C C `cbor:"c"`
}

func (c *Commitment[C]) Value() C {
	return c.c
}

func (c *Commitment[C]) Equal(other *Commitment[C]) bool {
	if c == nil || other == nil {
		return c == other
	}
	return c.c.Equal(other.c)
}

func (c *Commitment[C]) MarshalCBOR() ([]byte, error) {
	out, err := serde.MarshalCBOR(&commitmentDTO[C]{C: c.c})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal commitment")
	}
	return out, nil
}

func (c *Commitment[C]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*commitmentDTO[C]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal commitment")
	}
	cc, err := NewCommitment(dto.C)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment value in unmarshalled data")
	}
	*c = *cc
	return nil
}

func NewWitness[S encryption.Nonce](s S) (*Witness[S], error) {
	if utils.IsNil(s) {
		return nil, commitments.ErrIsNil.WithMessage("witness value must not be nil")
	}
	return &Witness[S]{s: s}, nil
}

type Witness[N encryption.Nonce] struct {
	s N
}

type witnessDTO[N encryption.Nonce] struct {
	S N `cbor:"s"`
}

func (w *Witness[N]) Value() N {
	return w.s
}

func (w *Witness[N]) MarshalCBOR() ([]byte, error) {
	out, err := serde.MarshalCBOR(&witnessDTO[N]{S: w.s})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal witness")
	}
	return out, nil
}

func (w *Witness[N]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*witnessDTO[N]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal witness")
	}
	ww, err := NewWitness(dto.S)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid witness value in unmarshalled data")
	}
	*w = *ww
	return nil
}

func NewMessage[P encryption.Plaintext](m P) (*Message[P], error) {
	if utils.IsNil(m) {
		return nil, commitments.ErrIsNil.WithMessage("message value must not be nil")
	}
	return &Message[P]{m: m}, nil
}

type Message[P encryption.Plaintext] struct {
	m P
}

type messageDTO[P encryption.Plaintext] struct {
	M P `cbor:"m"`
}

func (m *Message[P]) Value() P {
	return m.m
}

func (m *Message[P]) MarshalCBOR() ([]byte, error) {
	out, err := serde.MarshalCBOR(&messageDTO[P]{M: m.m})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal message")
	}
	return out, nil
}

func (m *Message[P]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*messageDTO[P]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal message")
	}
	mm, err := NewMessage(dto.M)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid message value in unmarshalled data")
	}
	*m = *mm
	return nil
}
