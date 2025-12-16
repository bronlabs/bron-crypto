package pedersen

import (
	"encoding"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

// Message wraps a scalar plaintext committed with Pedersen commitments.
type Message[S algebra.PrimeFieldElement[S]] struct {
	v S
}

type messageDTO[S algebra.PrimeFieldElement[S]] struct {
	V S `cbor:"v"`
}

// NewMessage constructs a message from the provided scalar value.
func NewMessage[S algebra.PrimeFieldElement[S]](v S) *Message[S] {
	return &Message[S]{
		v: v,
	}
}

// Value returns the underlying scalar.
func (m *Message[S]) Value() S {
	return m.v
}

// Op adds another message in the underlying field.
func (m *Message[S]) Op(other *Message[S]) *Message[S] {
	return m.Add(other)
}

// Add performs field addition with another message.
func (m *Message[S]) Add(other *Message[S]) *Message[S] {
	if other == nil {
		return m
	}
	return &Message[S]{
		v: m.v.Add(other.v),
	}
}

// OtherOp multiplies with another message in the field.
func (m *Message[S]) OtherOp(other *Message[S]) *Message[S] {
	return m.Mul(other)
}

// Mul multiplies two messages in the underlying field.
func (m *Message[S]) Mul(other *Message[S]) *Message[S] {
	if other == nil {
		return m
	}
	return &Message[S]{
		v: m.v.Mul(other.v),
	}
}

// Clone returns a deep copy of the message.
func (m *Message[S]) Clone() *Message[S] {
	if m == nil {
		return nil
	}
	return &Message[S]{
		v: m.v.Clone(),
	}
}

// Equal reports whether the two messages represent the same scalar (and handles nils).
func (m *Message[S]) Equal(other *Message[S]) bool {
	if m == nil || other == nil {
		return m == other
	}
	return m.v.Equal(other.v)
}

// HashCode returns a hash of the message value.
func (m *Message[S]) HashCode() base.HashCode {
	return m.v.HashCode()
}

// Bytes serialises the message to bytes using the scalar encoding.
func (m *Message[S]) Bytes() []byte {
	return m.v.Bytes()
}

// MarshalBinary serialises the message using the scalar's binary marshaler when available.
func (m *Message[S]) MarshalBinary() ([]byte, error) {
	scalarMarshaler, ok := any(m.v).(encoding.BinaryMarshaler)
	if !ok {
		return nil, errs.NewType("cannot marshal underlying scalar message")
	}
	data, err := scalarMarshaler.MarshalBinary()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal scalar message to binary")
	}
	return data, nil
}

// MarshalCBOR encodes the message into CBOR format.
func (m *Message[S]) MarshalCBOR() ([]byte, error) {
	dto := &messageDTO[S]{
		V: m.v,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal Pedersen message")
	}
	return data, nil
}

// UnmarshalCBOR decodes a CBOR message into the receiver.
func (m *Message[S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*messageDTO[S]](data)
	if err != nil {
		return err
	}

	m2 := NewMessage(dto.V)
	*m = *m2
	return nil
}
