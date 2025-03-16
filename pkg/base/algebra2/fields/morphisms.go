package fields

import (
	"fmt"

	algebra "github.com/bronlabs/krypton-primitives/pkg/base/algebra2"
	"github.com/bronlabs/krypton-primitives/pkg/base/algebra2/groups"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	saferith_utils "github.com/bronlabs/krypton-primitives/pkg/base/utils/saferith"
)

func NewUnitSubGroup[FE FieldElement[FE]](fe FE) *UnitSubGroup[FE] {
	f, err := GetField(fe)
	if err != nil {
		panic(errs.WrapType(err, "failed to get field from field element"))
	}
	out := &UnitSubGroup[FE]{
		F: f,
	}
	var _ groups.MultiplicativeGroup[*UnitSubGroupElement[FE]] = out
	return out
}

func NewUnitSubGroupElement[FE FieldElement[FE]](fe FE) (*UnitSubGroupElement[FE], error) {
	if fe.IsZero() {
		return nil, errs.NewIsZero("argument is zero")
	}
	out := &UnitSubGroupElement[FE]{
		Fe: fe,
	}
	var _ groups.MultiplicativeGroupElement[*UnitSubGroupElement[FE]] = out
	return out, nil
}

type UnitSubGroup[FE FieldElement[FE]] struct {
	F Field[FE]
}

func (g UnitSubGroup[FE]) Name() string {
	return fmt.Sprintf("U(%s)", g.F.Name())
}

func (g UnitSubGroup[FE]) Order() algebra.Cardinal {
	if g.F.Order() == algebra.Infinite {
		return algebra.Infinite
	}
	return saferith_utils.NatDec(g.F.Order())
}

func (g UnitSubGroup[FE]) OpIdentity() *UnitSubGroupElement[FE] {
	return g.One()
}

func (g UnitSubGroup[FE]) One() *UnitSubGroupElement[FE] {
	return &UnitSubGroupElement[FE]{
		Fe: g.F.One(),
	}
}

func (g UnitSubGroup[FE]) Operator() algebra.BinaryOperator[*UnitSubGroupElement[FE]] {
	return algebra.Mul[*UnitSubGroupElement[FE]]
}

type UnitSubGroupElement[FE FieldElement[FE]] struct {
	Fe FE
}

func (ge UnitSubGroupElement[FE]) FieldElement() FE {
	return ge.Fe
}

func (ge UnitSubGroupElement[FE]) Structure() algebra.Structure[*UnitSubGroupElement[FE]] {
	return &UnitSubGroup[FE]{}
}

func (ge UnitSubGroupElement[FE]) MarshalBinary() (data []byte, err error) {
	panic("implement me")
}

func (ge UnitSubGroupElement[FE]) UnmarshalBinary(data []byte) error {
	panic("implement me")
}

func (ge UnitSubGroupElement[FE]) Clone() *UnitSubGroupElement[FE] {
	return &UnitSubGroupElement[FE]{
		Fe: ge.Fe.Clone(),
	}
}

func (ge UnitSubGroupElement[FE]) Equal(rhs *UnitSubGroupElement[FE]) bool {
	return ge.Fe.Equal(rhs.Fe)
}

func (ge UnitSubGroupElement[FE]) HashCode() uint64 {
	panic("implement me")
}

func (ge UnitSubGroupElement[FE]) Op(rhs *UnitSubGroupElement[FE]) *UnitSubGroupElement[FE] {
	return ge.Mul(rhs)
}

func (ge UnitSubGroupElement[FE]) Order() algebra.Cardinal {
	panic("implement me")
}

func (ge UnitSubGroupElement[FE]) IsOpIdentity() bool {
	return ge.IsOne()
}

func (ge UnitSubGroupElement[FE]) TryOpInv() (*UnitSubGroupElement[FE], error) {
	return ge.Inv(), nil
}

func (ge UnitSubGroupElement[FE]) OpInv() *UnitSubGroupElement[FE] {
	return ge.Inv()
}

func (ge UnitSubGroupElement[FE]) Mul(rhs *UnitSubGroupElement[FE]) *UnitSubGroupElement[FE] {
	return &UnitSubGroupElement[FE]{
		Fe: ge.Fe.Mul(rhs.Fe),
	}
}

func (ge UnitSubGroupElement[FE]) Square() *UnitSubGroupElement[FE] {
	return &UnitSubGroupElement[FE]{
		Fe: ge.Fe.Square(),
	}
}

func (ge UnitSubGroupElement[FE]) IsOne() bool {
	return ge.Fe.IsOne()
}

func (ge UnitSubGroupElement[FE]) TryInv() (*UnitSubGroupElement[FE], error) {
	q, err := ge.Fe.TryInv()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to invert unit subgroup element")
	}
	return &UnitSubGroupElement[FE]{
		Fe: q,
	}, nil
}

func (ge UnitSubGroupElement[FE]) Inv() *UnitSubGroupElement[FE] {
	out, err := ge.TryInv()
	if err != nil {
		panic(errs.NewFailed("failed to invert unit subgroup element"))
	}
	return out
}

func (ge UnitSubGroupElement[FE]) TryDiv(e *UnitSubGroupElement[FE]) (*UnitSubGroupElement[FE], error) {
	q, err := ge.Fe.TryDiv(e.Fe)
	if err != nil {
		return nil, err
	}
	return &UnitSubGroupElement[FE]{
		Fe: q,
	}, nil
}

func (ge UnitSubGroupElement[FE]) Div(e *UnitSubGroupElement[FE]) *UnitSubGroupElement[FE] {
	out, err := ge.TryDiv(e)
	if err != nil {
		panic(errs.NewFailed("failed to divide unit subgroup elements"))
	}
	return out
}
