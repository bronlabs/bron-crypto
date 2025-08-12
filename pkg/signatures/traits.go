package signatures

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

type PublicKeyTrait[PKV algebra.PrimeGroupElement[PKV, S], S algebra.PrimeFieldElement[S]] struct {
	V PKV
	base.IncomparableTrait
}

func (pk *PublicKeyTrait[PKV, S]) Group() algebra.PrimeGroup[PKV, S] {
	group, ok := pk.V.Structure().(algebra.PrimeGroup[PKV, S])
	if !ok {
		panic("PublicKeyTrait must be based on a PrimeGroupElement")
	}
	return group
}

func (pk *PublicKeyTrait[PKV, S]) String() string {
	if pk == nil {
		return "<nil>"
	}
	return pk.V.String()
}

func (pk *PublicKeyTrait[PKV, S]) Value() PKV {
	return pk.V
}

func (pk *PublicKeyTrait[PKV, S]) Equal(other *PublicKeyTrait[PKV, S]) bool {
	if pk == nil || other == nil {
		return pk == other
	}
	return pk.V.Equal(other.V)
}

func (pk *PublicKeyTrait[PKV, S]) Clone() *PublicKeyTrait[PKV, S] {
	if pk == nil {
		return nil
	}
	return &PublicKeyTrait[PKV, S]{V: pk.V.Clone()}
}

func (pk *PublicKeyTrait[PKV, S]) HashCode() base.HashCode {
	return pk.V.HashCode()
}

type PrivateKeyTrait[PKV algebra.PrimeGroupElement[PKV, S], S algebra.PrimeFieldElement[S]] struct {
	V S
	PublicKeyTrait[PKV, S]
}

func (sk *PrivateKeyTrait[PKV, S]) ScalarField() algebra.PrimeField[S] {
	return algebra.StructureMustBeAs[algebra.PrimeField[S]](sk.V.Structure())
}

func (sk *PrivateKeyTrait[PKV, S]) Value() S {
	return sk.V
}

func (sk *PrivateKeyTrait[PKV, S]) Equal(other *PrivateKeyTrait[PKV, S]) bool {
	if sk == nil || other == nil {
		return sk == other
	}
	return sk.V.Equal(other.V) && sk.PublicKeyTrait.Equal(&other.PublicKeyTrait)
}

func (sk *PrivateKeyTrait[PKV, S]) Clone() *PrivateKeyTrait[PKV, S] {
	if sk == nil {
		return nil
	}
	return &PrivateKeyTrait[PKV, S]{
		V:              sk.V.Clone(),
		PublicKeyTrait: *sk.PublicKeyTrait.Clone(),
	}
}
