package pedersen

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

type Key[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	g E
	h E
}

type keyDTO[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	G E
	H E
}

func NewCommitmentKey[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](g, h E) (*Key[E, S], error) {
	if g.IsOpIdentity() || h.IsOpIdentity() {
		return nil, errs.NewIsIdentity("g or h cannot be the identity element")
	}
	if g.Equal(h) {
		return nil, errs.NewValue("g and h cannot be equal")
	}

	k := &Key[E, S]{
		g: g,
		h: h,
	}
	return k, nil
}

func (k *Key[E, S]) G() E {
	return k.g
}

func (k *Key[E, S]) H() E {
	return k.h
}

func (k *Key[E, S]) Bytes() []byte {
	return slices.Concat(k.g.Bytes(), k.h.Bytes())
}

func (k *Key[E, S]) Group() algebra.PrimeGroup[E, S] {
	return algebra.StructureMustBeAs[algebra.PrimeGroup[E, S]](k.g.Structure())
}

func (k *Key[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &keyDTO[E, S]{
		G: k.g,
		H: k.h,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal Pedersen key")
	}
	return data, nil
}

func (k *Key[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*keyDTO[E, S]](data)
	if err != nil {
		return err
	}
	k2, err := NewCommitmentKey(dto.G, dto.H)
	if err != nil {
		return err
	}

	*k = *k2
	return nil
}
