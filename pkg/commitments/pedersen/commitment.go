package pedersen

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

// Commitment represents a Pedersen commitment value held in the prime order group.
type Commitment[E FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]] struct {
	v E
}

type commitmentDTO[E FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]] struct {
	V E `cbor:"v"`
}

// NewCommitment wraps the provided group element as a commitment, rejecting the identity element.
func NewCommitment[E FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]](v E) (*Commitment[E, S], error) {
	if v.IsOpIdentity() {
		return nil, ErrInvalidArgument.WithMessage("commitment value cannot be the identity element")
	}
	return &Commitment[E, S]{v: v}, nil
}

// Value returns the underlying group element of the commitment.
func (c *Commitment[E, S]) Value() E {
	return c.v
}

// Equal reports whether both commitments hold the same group element (and handles nils).
func (c *Commitment[E, S]) Equal(other *Commitment[E, S]) bool {
	if c == nil || other == nil {
		return c == other
	}
	return c.v.Equal(other.v)
}

// Op combines two commitments using the group operation.
func (c *Commitment[E, S]) Op(other *Commitment[E, S]) *Commitment[E, S] {
	if other == nil {
		return c
	}
	return &Commitment[E, S]{v: c.v.Op(other.v)}
}

// ScalarOp raises the commitment to the given message scalar.
func (c *Commitment[E, S]) ScalarOp(message *Message[S]) *Commitment[E, S] {
	if message == nil {
		return c
	}
	return &Commitment[E, S]{v: c.v.ScalarOp(message.v)}
}

// Clone returns a deep copy of the commitment.
func (c *Commitment[E, S]) Clone() *Commitment[E, S] {
	if c == nil {
		return nil
	}
	return &Commitment[E, S]{v: c.v.Clone()}
}

// HashCode returns a hash of the commitment for use in maps or sets.
func (c *Commitment[E, S]) HashCode() base.HashCode {
	return c.v.HashCode()
}

// Bytes serialises the commitment to its canonical byte representation.
func (c *Commitment[E, S]) Bytes() []byte {
	return c.v.Bytes()
}

// MarshalCBOR encodes the commitment into CBOR format.
func (c *Commitment[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &commitmentDTO[E, S]{
		V: c.v,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal Pedersen commitment")
	}
	return data, nil
}

// UnmarshalCBOR decodes a CBOR commitment into the receiver.
func (c *Commitment[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*commitmentDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal Pedersen commitment")
	}
	c2, err := NewCommitment(dto.V)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid Pedersen commitment")
	}
	*c = *c2
	return nil
}
