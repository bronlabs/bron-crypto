package fields

import (
	algebra "github.com/bronlabs/krypton-primitives/pkg/base/algebra2"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

type (
	Field[FE algebra.FieldElement[FE]]        algebra.Field[FE]
	FieldElement[FE algebra.FieldElement[FE]] algebra.FieldElement[FE]

	FiniteField[FE algebra.FiniteFieldElement[FE]]        algebra.FiniteField[FE]
	FiniteFieldElement[FE algebra.FiniteFieldElement[FE]] algebra.FiniteFieldElement[FE]

	PrimeField[FE algebra.PrimeFieldElement[FE]]        algebra.PrimeField[FE]
	PrimeFieldElement[FE algebra.PrimeFieldElement[FE]] algebra.PrimeFieldElement[FE]
)

func GetField[FE FieldElement[FE]](fe FE) Field[FE] {
	return fe.Structure().(Field[FE])
}

func GetFiniteField[FE FiniteFieldElement[FE]](fe FE) FiniteField[FE] {
	return fe.Structure().(FiniteField[FE])
}

func GetPrimeField[FE PrimeFieldElement[FE]](fe FE) PrimeField[FE] {
	return fe.Structure().(PrimeField[FE])
}

type MultiplicativeGroupOfField[FE FieldElement[FE]] struct {
	F Field[FE]
}

func (g *MultiplicativeGroupOfField[FE]) Name() string {
	return "Multiplicative group of " + g.F.Name()
}

func (g *MultiplicativeGroupOfField[FE]) Order() algebra.Cardinal {
	panic("implement me")
	// return f.Order() - 1
}

type NonZeroFieldElement[FE FieldElement[FE]] struct {
	Fe FE
}

func AsMulGroupElement[FE FieldElement[FE]](fe FE) (*NonZeroFieldElement[FE], error) {
	if fe.IsZero() {
		return nil, errs.NewFailed("argument is zero")
	}

	return &NonZeroFieldElement[FE]{
		Fe: fe,
	}, nil
}

func (ge *NonZeroFieldElement[FE]) FieldElement() FE {
	return ge.Fe
}

func (ge *NonZeroFieldElement[FE]) Structure() algebra.Structure[*NonZeroFieldElement[FE]] {
	return &MultiplicativeGroupOfField[FE]{
		F: GetField(ge.Fe),
	}
}

func (ge *NonZeroFieldElement[FE]) MarshalBinary() (data []byte, err error) {
	panic("implement me")
}

func (ge *NonZeroFieldElement[FE]) UnmarshalBinary(data []byte) error {
	panic("implement me")
}

func (ge *NonZeroFieldElement[FE]) Clone() *NonZeroFieldElement[FE] {
	return &NonZeroFieldElement[FE]{
		Fe: ge.Fe.Clone(),
	}
}

func (ge *NonZeroFieldElement[FE]) Equal(rhs *NonZeroFieldElement[FE]) bool {
	return ge.Fe.Equal(rhs.Fe)
}

func (ge *NonZeroFieldElement[FE]) HashCode() uint64 {
	panic("implement me")
}

func (ge *NonZeroFieldElement[FE]) Op(rhs *NonZeroFieldElement[FE]) *NonZeroFieldElement[FE] {
	return ge.Mul(rhs)
}

func (ge *NonZeroFieldElement[FE]) Order() algebra.Cardinal {
	panic("implement me")
}

func (ge *NonZeroFieldElement[FE]) IsOpIdentity() bool {
	return ge.IsOne()
}

func (ge *NonZeroFieldElement[FE]) OpInv() *NonZeroFieldElement[FE] {
	return ge.Inv()
}

func (ge *NonZeroFieldElement[FE]) Mul(rhs *NonZeroFieldElement[FE]) *NonZeroFieldElement[FE] {
	return &NonZeroFieldElement[FE]{
		Fe: ge.Fe.Mul(rhs.Fe),
	}
}

func (ge *NonZeroFieldElement[FE]) Square() *NonZeroFieldElement[FE] {
	return &NonZeroFieldElement[FE]{
		Fe: ge.Fe.Square(),
	}
}

func (ge *NonZeroFieldElement[FE]) IsOne() bool {
	return ge.Fe.IsOne()
}

func (ge *NonZeroFieldElement[FE]) Inv() *NonZeroFieldElement[FE] {
	// TODO(aalireza): FieldElement is missing TryInv method
	//q, _ := ge.Fe.TryInv()
	//return &NonZeroFieldElement[FE]{
	//	Fe: q,
	//}
	panic("WTF?")
}

func (ge *NonZeroFieldElement[FE]) Div(e *NonZeroFieldElement[FE]) *NonZeroFieldElement[FE] {
	q, _ := ge.Fe.TryDiv(e.Fe)
	return &NonZeroFieldElement[FE]{
		Fe: q,
	}
}
