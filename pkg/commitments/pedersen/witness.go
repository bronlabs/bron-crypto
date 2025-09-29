package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/fxamacker/cbor/v2"
)

type Witness[S algebra.PrimeFieldElement[S]] struct {
	v S
}

type witnessDTO[S algebra.PrimeFieldElement[S]] struct {
	V S `cbor:"w"`
}

func NewWitness[S algebra.PrimeFieldElement[S]](v S) (*Witness[S], error) {
	if v.IsZero() {
		return nil, errs.NewIsZero("witness value cannot be zero")
	}
	w := &Witness[S]{
		v: v,
	}
	return w, nil
}

func (w *Witness[S]) Value() S {
	return w.v
}

func (w *Witness[S]) Op(other *Witness[S]) *Witness[S] {
	return w.Add(other)
}

func (w *Witness[S]) Add(other *Witness[S]) *Witness[S] {
	if other == nil {
		return w
	}
	return &Witness[S]{
		v: w.v.Add(other.v),
	}
}

func (w *Witness[S]) OtherOp(other *Witness[S]) *Witness[S] {
	return w.Mul(other)
}

func (w *Witness[S]) Mul(other *Witness[S]) *Witness[S] {
	if other == nil {
		return w
	}
	return &Witness[S]{
		v: w.v.Mul(other.v),
	}
}

func (w *Witness[S]) Equal(other *Witness[S]) bool {
	if w == nil || other == nil {
		return w == other
	}
	return w.v.Equal(other.v)
}

func (w *Witness[S]) Clone() *Witness[S] {
	if w == nil {
		return nil
	}
	return &Witness[S]{
		v: w.v.Clone(),
	}
}

func (w *Witness[S]) HashCode() base.HashCode {
	return w.v.HashCode()
}

func (w *Witness[S]) MarshalCBOR() ([]byte, error) {
	dto := &witnessDTO[S]{
		V: w.v,
	}
	return cbor.Marshal(dto)
}

func (w *Witness[S]) UnmarshalCBOR(data []byte) error {
	var dto witnessDTO[S]
	if err := cbor.Unmarshal(data, &dto); err != nil {
		return err
	}
	w2, err := NewWitness(dto.V)
	if err != nil {
		return err
	}
	*w = *w2
	return nil
}
