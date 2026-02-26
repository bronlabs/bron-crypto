package constructions

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	acrtp "github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/errs-go/errs"
)

func NewFieldUnitSubGroup[F algebra.Field[FE], FE acrtp.FieldElement[FE]](f F) (*FieldUnitSubGroup[FE], error) {
	if utils.IsNil(f) {
		return nil, ErrInvalidArgument.WithMessage("field is nil")
	}
	out := &FieldUnitSubGroup[FE]{
		f: f,
	}
	var _ algebra.MultiplicativeGroup[*FieldUnitSubGroupElement[FE]] = out
	return out, nil
}

type FieldUnitSubGroup[FE acrtp.FieldElement[FE]] struct {
	f algebra.Field[FE]
}

func (FieldUnitSubGroup[FE]) New(fe FE) (*FieldUnitSubGroupElement[FE], error) {
	if fe.IsZero() {
		return nil, ErrInvalidArgument.WithMessage("argument is zero")
	}
	out := &FieldUnitSubGroupElement[FE]{
		fe: fe,
	}
	var _ algebra.MultiplicativeGroupElement[*FieldUnitSubGroupElement[FE]] = out
	return out, nil
}

func (g FieldUnitSubGroup[FE]) Name() string {
	return fmt.Sprintf("U(%s)", g.f.Name())
}

func (g FieldUnitSubGroup[FE]) ElementSize() int {
	return g.f.ElementSize()
}

func (g FieldUnitSubGroup[FE]) Order() cardinal.Cardinal {
	if !g.f.Order().IsFinite() {
		return cardinal.Infinite()
	}
	knownOrder, ok := g.f.Order().(cardinal.Known)
	if !ok {
		panic("field order is not known")
	}
	return knownOrder.Sub(cardinal.New(1))
}

func (g FieldUnitSubGroup[FE]) OpIdentity() *FieldUnitSubGroupElement[FE] {
	return g.One()
}

func (g FieldUnitSubGroup[FE]) One() *FieldUnitSubGroupElement[FE] {
	return &FieldUnitSubGroupElement[FE]{
		fe: g.f.One(),
	}
}

func (g FieldUnitSubGroup[FE]) FromBytes(x []byte) (*FieldUnitSubGroupElement[FE], error) {
	fe, err := g.f.FromBytes(x)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create field element from bytes")
	}
	return g.New(fe)
}

type FieldUnitSubGroupElement[FE acrtp.FieldElement[FE]] struct {
	fe FE
}

func (ge FieldUnitSubGroupElement[FE]) FieldElement() FE {
	return ge.fe
}

func (ge FieldUnitSubGroupElement[FE]) Bytes() []byte {
	return ge.fe.Bytes()
}

func (ge FieldUnitSubGroupElement[FE]) Structure() algebra.Structure[*FieldUnitSubGroupElement[FE]] {
	f, ok := ge.fe.Structure().(algebra.Field[FE])
	if !ok {
		panic(ErrInvalidType.WithMessage("field element does not have a field structure"))
	}
	return &FieldUnitSubGroup[FE]{f: f}
}

func (ge FieldUnitSubGroupElement[FE]) Clone() *FieldUnitSubGroupElement[FE] {
	return &FieldUnitSubGroupElement[FE]{
		fe: ge.fe.Clone(),
	}
}

func (ge FieldUnitSubGroupElement[FE]) Equal(rhs *FieldUnitSubGroupElement[FE]) bool {
	return ge.fe.Equal(rhs.fe)
}

func (ge FieldUnitSubGroupElement[FE]) HashCode() base.HashCode {
	return ge.fe.HashCode() ^ base.HashCode(0xcafebebe)
}

func (ge FieldUnitSubGroupElement[FE]) Op(rhs *FieldUnitSubGroupElement[FE]) *FieldUnitSubGroupElement[FE] {
	return ge.Mul(rhs)
}

func (ge FieldUnitSubGroupElement[FE]) Order() cardinal.Cardinal {
	if !ge.fe.Structure().Order().IsFinite() {
		return cardinal.Infinite()
	}
	knownOrder, ok := ge.fe.Structure().Order().(cardinal.Known)
	if !ok {
		panic("field order is not known")
	}
	return knownOrder.Sub(cardinal.New(1))
}

func (ge FieldUnitSubGroupElement[FE]) IsOpIdentity() bool {
	return ge.IsOne()
}

func (ge FieldUnitSubGroupElement[FE]) TryOpInv() (*FieldUnitSubGroupElement[FE], error) {
	return ge.Inv(), nil
}

func (ge FieldUnitSubGroupElement[FE]) OpInv() *FieldUnitSubGroupElement[FE] {
	return ge.Inv()
}

func (ge FieldUnitSubGroupElement[FE]) Mul(rhs *FieldUnitSubGroupElement[FE]) *FieldUnitSubGroupElement[FE] {
	return &FieldUnitSubGroupElement[FE]{
		fe: ge.fe.Mul(rhs.fe),
	}
}

func (ge FieldUnitSubGroupElement[FE]) Square() *FieldUnitSubGroupElement[FE] {
	return &FieldUnitSubGroupElement[FE]{
		fe: ge.fe.Square(),
	}
}

func (ge FieldUnitSubGroupElement[FE]) IsOne() bool {
	return ge.fe.IsOne()
}

func (ge FieldUnitSubGroupElement[FE]) TryInv() (*FieldUnitSubGroupElement[FE], error) {
	q, err := ge.fe.TryInv()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to invert unit subgroup element")
	}
	return &FieldUnitSubGroupElement[FE]{
		fe: q,
	}, nil
}

func (ge FieldUnitSubGroupElement[FE]) Inv() *FieldUnitSubGroupElement[FE] {
	out, err := ge.TryInv()
	if err != nil {
		panic(ErrInvalidArgument.WithMessage("failed to invert unit subgroup element"))
	}
	return out
}

func (ge FieldUnitSubGroupElement[FE]) TryDiv(e *FieldUnitSubGroupElement[FE]) (*FieldUnitSubGroupElement[FE], error) {
	q, err := ge.fe.TryDiv(e.fe)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to divide unit subgroup elements")
	}
	return &FieldUnitSubGroupElement[FE]{
		fe: q,
	}, nil
}

func (ge FieldUnitSubGroupElement[FE]) Div(e *FieldUnitSubGroupElement[FE]) *FieldUnitSubGroupElement[FE] {
	out, err := ge.TryDiv(e)
	if err != nil {
		panic(ErrInvalidArgument.WithMessage("failed to divide unit subgroup elements"))
	}
	return out
}

func (ge FieldUnitSubGroupElement[FE]) String() string {
	return fmt.Sprintf("U(%s)", ge.fe.String())
}
