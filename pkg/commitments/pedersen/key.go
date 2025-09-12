package pedersen

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/fxamacker/cbor/v2"
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

func NewCommitmentKeyFromBytes[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](group algebra.PrimeGroup[E, S], input []byte) (*Key[E, S], error) {
	if group == nil {
		return nil, errs.NewIsNil("group cannot be nil")
	}

	// TODO: this basically makes it useless
	if len(input) != 2*group.ElementSize() {
		return nil, errs.NewArgument("input length must be twice the group element size")
	}

	g, err := group.FromBytes(input[:group.ElementSize()])
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot deserialize g from bytes")
	}
	h, err := group.FromBytes(input[group.ElementSize():])
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot deserialize h from bytes")
	}
	return NewCommitmentKey(g, h)
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

func (k *Key[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &keyDTO[E, S]{
		G: k.g,
		H: k.h,
	}
	return cbor.Marshal(dto)
}

func (k *Key[E, S]) UnmarshalCBOR(data []byte) error {
	var dto keyDTO[E, S]
	if err := cbor.Unmarshal(data, &dto); err != nil {
		return err
	}
	k2, err := NewCommitmentKey(dto.G, dto.H)
	if err != nil {
		return err
	}
	
	*k = *k2
	return nil
}
