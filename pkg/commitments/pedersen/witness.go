package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/errs-go/pkg/errs"
)

// Witness holds the randomness used to hide the committed message.
type Witness[S algebra.PrimeFieldElement[S]] struct {
	v S
}

type witnessDTO[S algebra.PrimeFieldElement[S]] struct {
	V S `cbor:"w"`
}

// NewWitness constructs a witness, rejecting zero values to prevent degenerate commitments.
func NewWitness[S algebra.PrimeFieldElement[S]](v S) (*Witness[S], error) {
	if v.IsZero() {
		return nil, ErrInvalidArgument.WithMessage("witness value cannot be zero")
	}
	w := &Witness[S]{
		v: v,
	}
	return w, nil
}

// Value returns the witness scalar.
func (w *Witness[S]) Value() S {
	return w.v
}

// Op adds two witnesses in the field.
func (w *Witness[S]) Op(other *Witness[S]) *Witness[S] {
	return w.Add(other)
}

// Add performs field addition with another witness.
func (w *Witness[S]) Add(other *Witness[S]) *Witness[S] {
	if other == nil {
		return w
	}
	return &Witness[S]{
		v: w.v.Add(other.v),
	}
}

// OtherOp multiplies with another witness in the field.
func (w *Witness[S]) OtherOp(other *Witness[S]) *Witness[S] {
	return w.Mul(other)
}

// Mul multiplies two witnesses in the underlying field.
func (w *Witness[S]) Mul(other *Witness[S]) *Witness[S] {
	if other == nil {
		return w
	}
	return &Witness[S]{
		v: w.v.Mul(other.v),
	}
}

// Equal reports whether the two witnesses hold the same scalar (and handles nils).
func (w *Witness[S]) Equal(other *Witness[S]) bool {
	if w == nil || other == nil {
		return w == other
	}
	return w.v.Equal(other.v)
}

// Clone returns a deep copy of the witness.
func (w *Witness[S]) Clone() *Witness[S] {
	if w == nil {
		return nil
	}
	return &Witness[S]{
		v: w.v.Clone(),
	}
}

// HashCode returns a hash of the witness value.
func (w *Witness[S]) HashCode() base.HashCode {
	return w.v.HashCode()
}

// MarshalCBOR encodes the witness into CBOR format.
func (w *Witness[S]) MarshalCBOR() ([]byte, error) {
	dto := &witnessDTO[S]{
		V: w.v,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal Pedersen witness")
	}
	return data, nil
}

// UnmarshalCBOR decodes a CBOR witness into the receiver.
func (w *Witness[S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*witnessDTO[S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot unmarshal witness")
	}

	w2, err := NewWitness(dto.V)
	if err != nil {
		return err
	}
	*w = *w2
	return nil
}
