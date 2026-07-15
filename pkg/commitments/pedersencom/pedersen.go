package pedersencom

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
)

// Name identifies the prime-order Pedersen commitment scheme.
const Name commitments.Name = "Prime-order Pedersen commitment scheme"

// NewCommitment wraps a prime-order group element as a commitment value,
// rejecting a nil element. It is the canonical constructor and is used by the
// CBOR decoder so that every Commitment holds a non-nil element.
func NewCommitment[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](v E) (*Commitment[E, S], error) {
	if utils.IsNil(v) {
		return nil, ErrIsNil.WithMessage("commitment value must not be nil")
	}
	return &Commitment[E, S]{v: v}, nil
}

// Commitment is a Pedersen commitment C = g^m · h^r, represented as a single
// prime-order group element. It is a public value: it is perfectly hiding (it
// reveals nothing about m while the witness r stays secret) and computationally
// binding under the discrete-log assumption on the underlying group.
type Commitment[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	v E
}

type commitmentDTO[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	V E `cbor:"v"`
}

// Value returns the underlying group element g^m · h^r.
func (c *Commitment[E, S]) Value() E {
	return c.v
}

// Equal reports whether two commitments are the same group element, treating a
// nil commitment as equal only to another nil commitment. Commitments are
// public, so the comparison need not be constant time.
func (c *Commitment[E, S]) Equal(other *Commitment[E, S]) bool {
	if c == nil || other == nil {
		return c == other
	}
	return c.v.Equal(other.v)
}

// HashCode returns a non-cryptographic hash of the commitment for use as a map
// key; it is derived from the group element and carries no security guarantee.
func (c *Commitment[E, S]) HashCode() base.HashCode {
	return c.v.HashCode()
}

// MarshalCBOR encodes the commitment's group element.
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

// UnmarshalCBOR decodes a commitment and rejects a nil element via NewCommitment.
// This is a deserialisation trust boundary: that the decoded element is on-curve
// and in the prime-order subgroup is enforced by the element decoder, not here.
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

// NewWitness wraps a scalar-field element as commitment randomness, rejecting a
// nil scalar.
func NewWitness[S algebra.PrimeFieldElement[S]](v S) (*Witness[S], error) {
	if utils.IsNil(v) {
		return nil, ErrIsNil.WithMessage("witness value must not be nil")
	}
	return &Witness[S]{r: v}, nil
}

// Witness is the secret randomness r used in C = g^m · h^r. It must stay private
// until the commitment is opened: revealing it early, or reusing it across
// commitments, destroys the hiding property.
type Witness[S algebra.PrimeFieldElement[S]] struct {
	r S
}

type witnessDTO[S algebra.PrimeFieldElement[S]] struct {
	R S `cbor:"r"`
}

// Value returns the underlying scalar r. The result is secret.
func (w *Witness[S]) Value() S {
	return w.r
}

// Equal reports whether two witnesses hold the same scalar, treating a nil
// witness as equal only to another nil witness. Equality is delegated to the
// field element and is not guaranteed constant time, so avoid it on still-secret
// witnesses in timing-sensitive paths.
func (w *Witness[S]) Equal(other *Witness[S]) bool {
	if w == nil || other == nil {
		return w == other
	}
	return w.r.Equal(other.r)
}

// Add returns the witness r1 + r2 in the scalar field. This matches the
// randomness of the commitment obtained by combining two commitments via
// CommitmentOp. It panics if other is nil.
func (w *Witness[S]) Add(other *Witness[S]) *Witness[S] {
	if other == nil {
		panic("other witness must not be nil")
	}
	return &Witness[S]{r: w.r.Add(other.r)}
}

// Mul returns the witness r1 · r2 in the scalar field. It panics if other is nil.
func (w *Witness[S]) Mul(other *Witness[S]) *Witness[S] {
	if other == nil {
		panic("other witness must not be nil")
	}
	return &Witness[S]{r: w.r.Mul(other.r)}
}

// HashCode returns a non-cryptographic hash of the witness for use as a map key.
func (w *Witness[S]) HashCode() base.HashCode {
	return w.r.HashCode()
}

// MarshalCBOR encodes the witness scalar. The output is secret material.
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

// UnmarshalCBOR decodes a witness scalar, rejecting a nil value via NewWitness.
// This is a deserialisation trust boundary for secret material.
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

// NewMessage wraps a scalar-field element as the committed value, rejecting a nil
// scalar.
func NewMessage[S algebra.PrimeFieldElement[S]](v S) (*Message[S], error) {
	if utils.IsNil(v) {
		return nil, ErrIsNil.WithMessage("message value must not be nil")
	}
	return &Message[S]{m: v}, nil
}

// Message is the committed value m, an element of the group's scalar field.
type Message[S algebra.PrimeFieldElement[S]] struct {
	m S
}

type messageDTO[S algebra.PrimeFieldElement[S]] struct {
	M S `cbor:"m"`
}

// Value returns the underlying scalar m.
func (m *Message[S]) Value() S {
	return m.m
}

// Equal reports whether two messages hold the same scalar, treating a nil
// message as equal only to another nil message.
func (m *Message[S]) Equal(other *Message[S]) bool {
	if m == nil || other == nil {
		return m == other
	}
	return m.m.Equal(other.m)
}

// Add returns the message m1 + m2 in the scalar field. By the additive
// homomorphism, committing to this sum equals combining the two commitments via
// CommitmentOp. It panics if other is nil.
func (m *Message[S]) Add(other *Message[S]) *Message[S] {
	if other == nil {
		panic("other message must not be nil")
	}
	return &Message[S]{m: m.m.Add(other.m)}
}

// Mul returns the message m1 · m2 in the scalar field. It panics if other is nil.
func (m *Message[S]) Mul(other *Message[S]) *Message[S] {
	if other == nil {
		panic("other message must not be nil")
	}
	return &Message[S]{m: m.m.Mul(other.m)}
}

// HashCode returns a non-cryptographic hash of the message for use as a map key.
func (m *Message[S]) HashCode() base.HashCode {
	return m.m.HashCode()
}

// MarshalCBOR encodes the message scalar.
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

// UnmarshalCBOR decodes a message scalar, rejecting a nil value via NewMessage.
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
