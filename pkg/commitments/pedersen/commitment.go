package pedersen

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
)

// Commitment represents a Pedersen commitment value held in the prime order group.
type Commitment[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	v E
}

type commitmentDTO[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	V E `cbor:"v"`
}

// NewCommitment wraps the provided group element as a commitment, rejecting the identity element.
func NewCommitment[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](v E) (*Commitment[E, S], error) {
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

// ReRandomiseWithWitness blinds the commitment using the provided witness randomness.
func (c *Commitment[E, S]) ReRandomiseWithWitness(key *Key[E, S], r *Witness[S]) (*Commitment[E, S], error) {
	if r == nil {
		return nil, ErrInvalidArgument.WithMessage("witness cannot be nil")
	}
	if key == nil {
		return nil, ErrInvalidArgument.WithMessage("key cannot be nil")
	}
	if c == nil {
		return nil, ErrInvalidArgument.WithMessage("commitment cannot be nil")
	}
	newCom, err := NewCommitment(c.v.Op(key.h.ScalarOp(r.v)))
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot re-randomise commitment")
	}
	return newCom, nil
}

// ReRandomise samples fresh randomness and blinds the commitment, returning the new commitment and witness.
func (c *Commitment[E, S]) ReRandomise(key *Key[E, S], prng io.Reader) (*Commitment[E, S], *Witness[S], error) {
	if key == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("key cannot be nil")
	}
	if prng == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("prng cannot be nil")
	}

	group := algebra.StructureMustBeAs[algebra.PrimeGroup[E, S]](key.h.Structure())
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	wv, err := algebrautils.RandomNonIdentity(field, prng)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot generate random witness")
	}
	witness, err := NewWitness(wv)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot create witness")
	}
	commitment, err := c.ReRandomiseWithWitness(key, witness)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot re-randomise commitment with witness")
	}
	return commitment, witness, nil
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
		return nil, errs2.Wrap(err).WithMessage("failed to marshal Pedersen commitment")
	}
	return data, nil
}

// UnmarshalCBOR decodes a CBOR commitment into the receiver.
func (c *Commitment[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*commitmentDTO[E, S]](data)
	if err != nil {
		return errs2.Wrap(err).WithMessage("failed to unmarshal Pedersen commitment")
	}
	c2, err := NewCommitment(dto.V)
	if err != nil {
		return err
	}
	*c = *c2
	return nil
}
