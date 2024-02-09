package k256

import (
	"io"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl/fp"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

var (
	k256BaseFieldInitOnce sync.Once
	k256BaseFieldInstance BaseField
)

var _ curves.BaseField = (*BaseField)(nil)

type BaseField struct {
	_ types.Incomparable
}

func k256BaseFieldInit() {
	k256BaseFieldInstance = BaseField{}
}

func NewBaseField() *BaseField {
	k256BaseFieldInitOnce.Do(k256BaseFieldInit)
	return &k256BaseFieldInstance
}

func (*BaseField) Curve() curves.Curve {
	return NewCurve()
}

// === Basic Methods.

func (*BaseField) Name() string {
	return Name
}

func (*BaseField) Order() *saferith.Modulus {
	return fp.New().Params.Modulus
}

func (f *BaseField) Element() curves.BaseFieldElement {
	return f.AdditiveIdentity()
}

func (*BaseField) Operators() []algebra.Operator {
	return []algebra.Operator{algebra.Addition, algebra.Multiplication}
}

func (f *BaseField) OperateOver(operator algebra.Operator, xs ...curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	var current curves.BaseFieldElement
	switch operator {
	case algebra.Addition:
		current = f.AdditiveIdentity()
		for _, x := range xs {
			current = current.Add(x)
		}
	case algebra.Multiplication:
		current = f.MultiplicativeIdentity()
		for _, x := range xs {
			current = current.Mul(x)
		}
	case algebra.PointAddition:
		fallthrough
	default:
		return nil, errs.NewInvalidType("operator %v is not supported", operator)
	}
	return current, nil
}

func (*BaseField) Random(prng io.Reader) (curves.BaseFieldElement, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	var seed [base.WideFieldBytes]byte
	_, err := prng.Read(seed[:])
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not read from prng")
	}
	value, err := NewBaseFieldElement(0).SetBytesWide(seed[:])
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not set bytes")
	}
	return value, nil
}

func (*BaseField) Hash(x []byte) (curves.BaseFieldElement, error) {
	els, err := NewCurve().HashToFieldElements(1, x, nil)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "could not hash to field element in k256")
	}
	return els[0], nil
}

func (*BaseField) Select(choice bool, x0, x1 curves.BaseFieldElement) curves.BaseFieldElement {
	x0f, ok0 := x0.(*BaseFieldElement)
	x1f, ok1 := x1.(*BaseFieldElement)
	if !ok0 || !ok1 {
		panic("Not a k256 field element")
	}
	el := new(BaseFieldElement)
	el.V.Arithmetic.Selectznz(&el.V.Value, &x0f.V.Value, &x1f.V.Value, utils.BoolTo[int](choice))
	return el
}

// === Additive Groupoid Methods.

func (*BaseField) Add(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) curves.BaseFieldElement {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
}

// === Multiplicative Groupoid Methods.

func (*BaseField) Multiply(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) curves.BaseFieldElement {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
}

// === Additive Monoid Methods.

func (*BaseField) AdditiveIdentity() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: fp.New().SetZero(),
	}
}

// === Multiplicative Monoid Methods.

func (*BaseField) MultiplicativeIdentity() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: fp.New().SetOne(),
	}
}

// === Additive Group Methods.

func (*BaseField) Sub(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) curves.BaseFieldElement {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
}

// === Multiplicative Group Methods.

func (*BaseField) Div(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) curves.BaseFieldElement {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
}

// === Ring Methods.

func (*BaseField) QuadraticResidue(p curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	pp, ok := p.(*BaseFieldElement)
	if !ok {
		return nil, errs.NewInvalidType("given point is not from this field")
	}
	return pp.Sqrt()
}

// === Finite Field Methods.

func (f *BaseField) Characteristic() *saferith.Nat {
	return f.Order().Nat()
}

func (*BaseField) ExtensionDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(1)
}

func (f *BaseField) FrobeniusAutomorphism(e curves.BaseFieldElement) curves.BaseFieldElement {
	return e.Exp(new(BaseFieldElement).SetNat(f.Characteristic()))
}

func (f *BaseField) Trace(e curves.BaseFieldElement) curves.BaseFieldElement {
	result := e
	currentDegree := new(saferith.Nat).SetUint64(1)
	currentTerm := result
	for currentDegree.Eq(f.ExtensionDegree()) == 1 {
		currentTerm = f.FrobeniusAutomorphism(currentTerm)
		result = result.Add(currentTerm)
		currentDegree = utils.Saferith.NatIncrement(currentDegree)
	}
	return result
}

func (*BaseField) FieldBytes() int {
	return base.FieldBytes
}

func (*BaseField) WideFieldBytes() int {
	return base.WideFieldBytes
}

// === Zp Methods.

func (*BaseField) New(v uint64) curves.BaseFieldElement {
	return NewBaseFieldElement(v)
}

func (f *BaseField) Zero() curves.BaseFieldElement {
	return f.AdditiveIdentity()
}

func (f *BaseField) One() curves.BaseFieldElement {
	return f.MultiplicativeIdentity()
}

// === Ordering Methods.

func (f *BaseField) Top() curves.BaseFieldElement {
	return f.Zero().Sub(f.One())
}

func (f *BaseField) Bottom() curves.BaseFieldElement {
	return f.Zero()
}

func (*BaseField) Join(x, y curves.BaseFieldElement) curves.BaseFieldElement {
	return x.Join(y)
}

func (*BaseField) Meet(x, y curves.BaseFieldElement) curves.BaseFieldElement {
	return x.Meet(y)
}

func (*BaseField) Max(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) curves.BaseFieldElement {
	max := x
	for _, y := range ys {
		max = max.Max(y)
	}
	return max
}

func (*BaseField) Min(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) curves.BaseFieldElement {
	min := x
	for _, y := range ys {
		min = min.Min(y)
	}
	return min
}
