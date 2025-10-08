package pedersen

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

type Commitment[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	v E
}

type commitmentDTO[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	V E `cbor:"v"`
}

func NewCommitment[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](v E) (*Commitment[E, S], error) {
	if v.IsOpIdentity() {
		return nil, errs.NewIsIdentity("commitment value cannot be the identity element")
	}
	return &Commitment[E, S]{v: v}, nil
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

func (c *Commitment[E, S]) Op(other *Commitment[E, S]) *Commitment[E, S] {
	if other == nil {
		return c
	}
	return &Commitment[E, S]{v: c.v.Op(other.v)}
}

func (c *Commitment[E, S]) ScalarOp(message *Message[S]) *Commitment[E, S] {
	if message == nil {
		return c
	}
	return &Commitment[E, S]{v: c.v.ScalarOp(message.v)}
}

func (c *Commitment[E, S]) ReRandomiseWith(key *Key[E, S], r *Witness[S]) (*Commitment[E, S], error) {
	if r == nil {
		return nil, errs.NewIsNil("witness cannot be nil")
	}
	if key == nil {
		return nil, errs.NewIsNil("key cannot be nil")
	}
	if c == nil {
		return nil, errs.NewIsNil("commitment cannot be nil")
	}
	newCom := &Commitment[E, S]{v: c.v.Op(key.h.ScalarOp(r.v))}
	return newCom, nil
}

func (c *Commitment[E, S]) ReRandomise(key *Key[E, S], prng io.Reader) (*Commitment[E, S], *Witness[S], error) {
	if key == nil {
		return nil, nil, errs.NewIsNil("key cannot be nil")
	}
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng cannot be nil")
	}

	group := algebra.StructureMustBeAs[algebra.PrimeGroup[E, S]](key.h.Structure())
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	wv, err := field.Random(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot generate random witness")
	}
	witness := &Witness[S]{v: wv}
	commitment, err := c.ReRandomiseWith(key, witness)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot re-randomise commitment with witness")
	}
	return commitment, witness, nil
}

func (c *Commitment[E, S]) Clone() *Commitment[E, S] {
	if c == nil {
		return nil
	}
	return &Commitment[E, S]{v: c.v.Clone()}
}

func (c *Commitment[E, S]) HashCode() base.HashCode {
	return c.v.HashCode()
}

func (c *Commitment[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &commitmentDTO[E, S]{
		V: c.v,
	}
	return serde.MarshalCBOR(dto)
}

func (c *Commitment[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*commitmentDTO[E, S]](data)
	if err != nil {
		return err
	}
	c2, err := NewCommitment(dto.V)
	if err != nil {
		return err
	}
	*c = *c2
	return nil
}
