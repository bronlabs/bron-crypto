package pedersen

import (
	"encoding"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

type Message[S algebra.PrimeFieldElement[S]] struct {
	v S
}

type messageDTO[S algebra.PrimeFieldElement[S]] struct {
	V S `cbor:"v"`
}

func NewMessage[S algebra.PrimeFieldElement[S]](v S) *Message[S] {
	return &Message[S]{
		v: v,
	}
}

func (m *Message[S]) Value() S {
	return m.v
}

func (m *Message[S]) Op(other *Message[S]) *Message[S] {
	return m.Add(other)
}

func (m *Message[S]) Add(other *Message[S]) *Message[S] {
	if other == nil {
		return m
	}
	return &Message[S]{
		v: m.v.Add(other.v),
	}
}

func (m *Message[S]) OtherOp(other *Message[S]) *Message[S] {
	return m.Mul(other)
}
func (m *Message[S]) Mul(other *Message[S]) *Message[S] {
	if other == nil {
		return m
	}
	return &Message[S]{
		v: m.v.Mul(other.v),
	}
}

func (m *Message[S]) Clone() *Message[S] {
	if m == nil {
		return nil
	}
	return &Message[S]{
		v: m.v.Clone(),
	}
}

func (m *Message[S]) Equal(other *Message[S]) bool {
	if m == nil || other == nil {
		return m == other
	}
	return m.v.Equal(other.v)
}

func (m *Message[S]) HashCode() base.HashCode {
	return m.v.HashCode()
}

func (m *Message[S]) Bytes() []byte {
	return m.v.Bytes()
}

func (m *Message[S]) MarshalBinary() ([]byte, error) {
	scalarMarshaler, ok := any(m.v).(encoding.BinaryMarshaler)
	if !ok {
		return nil, errs.NewType("cannot marshal underlying scalar message")
	}
	return scalarMarshaler.MarshalBinary()
}

func (m *Message[S]) MarshalCBOR() ([]byte, error) {
	dto := &messageDTO[S]{
		V: m.v,
	}
	return serde.MarshalCBOR(dto)
}

func (m *Message[S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*messageDTO[S]](data)
	if err != nil {
		return err
	}

	m2 := NewMessage(dto.V)
	*m = *m2
	return nil
}
