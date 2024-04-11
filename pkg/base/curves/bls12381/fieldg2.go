package bls12381

import (
	"io"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	bimpl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

var (
	g2BaseFieldInitOnce sync.Once
	g2BaseFieldInstance BaseFieldG2
)

var (
	p2 = new(saferith.Nat).Mul(p.Nat(), p.Nat(), -1)
)

var _ curves.BaseField = (*BaseFieldG2)(nil)

type BaseFieldG2 struct {
	_ ds.Incomparable
}

func g2BaseFieldInit() {
	g2BaseFieldInstance = BaseFieldG2{}
}

func NewBaseFieldG2() *BaseFieldG2 {
	g2BaseFieldInitOnce.Do(g2BaseFieldInit)
	return &g2BaseFieldInstance
}

func (*BaseFieldG2) Curve() curves.Curve {
	return NewG2()
}

// ==== Basic Methods.

func (*BaseFieldG2) Name() string {
	return NameG2
}

func (*BaseFieldG2) Order() *saferith.Modulus {
	return saferith.ModulusFromNat(p2)
}

func (f *BaseFieldG2) Element() curves.BaseFieldElement {
	return f.AdditiveIdentity()
}

func (*BaseFieldG2) Operators() []algebra.Operator {
	return []algebra.Operator{algebra.Addition, algebra.Multiplication}
}

func (f *BaseFieldG2) OperateOver(operator algebra.Operator, xs ...curves.BaseFieldElement) (curves.BaseFieldElement, error) {
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
		return nil, errs.NewType("operator %v is not supported", operator)
	}
	return current, nil
}

func (f *BaseFieldG2) Random(prng io.Reader) (curves.BaseFieldElement, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	result, err := f.Element().(*BaseFieldElementG2).V.Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not generate random field element")
	}
	return &BaseFieldElementG2{V: result}, nil
}

func (*BaseFieldG2) Hash(x []byte) (curves.BaseFieldElement, error) {
	els, err := NewG2().HashToFieldElements(1, x, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not hash to field element in bls12381 G2")
	}
	return els[0], nil
}

func (*BaseFieldG2) Select(choice bool, x0, x1 curves.BaseFieldElement) curves.BaseFieldElement {
	x0p2, ok0 := x0.(*BaseFieldElementG2)
	x1p2, ok1 := x1.(*BaseFieldElementG2)
	if !ok0 || !ok1 {
		panic("Not a BLS12381 G2 field element")
	}
	return &BaseFieldElementG2{
		V: new(bimpl.Fp2).CMove(x0p2.V, x1p2.V, utils.BoolTo[int](choice)),
	}
}

// === Additive Groupoid Methods.

func (*BaseFieldG2) Add(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) curves.BaseFieldElement {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
}

// === Multiplicative Groupoid Methods.

func (*BaseFieldG2) Multiply(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) curves.BaseFieldElement {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
}

// === Additive Monoid Methods.

func (*BaseFieldG2) AdditiveIdentity() curves.BaseFieldElement {
	return &BaseFieldElementG2{
		V: new(bimpl.Fp2).SetZero(),
	}
}

// === Multiplicative Monoid Methods.

func (*BaseFieldG2) MultiplicativeIdentity() curves.BaseFieldElement {
	return &BaseFieldElementG2{
		V: new(bimpl.Fp2).SetOne(),
	}
}

// === Additive Group Methods.

func (*BaseFieldG2) Sub(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) curves.BaseFieldElement {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
}

// === Multiplicative Group Methods.

func (*BaseFieldG2) Div(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) curves.BaseFieldElement {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum
}

// === Ring Methods.

func (*BaseFieldG2) QuadraticResidue(p curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	pp, ok := p.(*BaseFieldElementG2)
	if !ok {
		return nil, errs.NewType("given point is not from this field")
	}
	return pp.Sqrt()
}

// === Finite Field Methods.

func (*BaseFieldG2) Characteristic() *saferith.Nat {
	return p.Nat()
}

func (*BaseFieldG2) ExtensionDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(2)
}

func (f *BaseFieldG2) FrobeniusAutomorphism(e curves.BaseFieldElement) curves.BaseFieldElement {
	return e.Exp(new(BaseFieldElementG2).SetNat(f.Characteristic()))
}

func (f *BaseFieldG2) Trace(e curves.BaseFieldElement) curves.BaseFieldElement {
	result := e
	currentDegree := saferithUtils.NatOne
	currentTerm := result
	for currentDegree.Eq(f.ExtensionDegree()) == 1 {
		currentTerm = f.FrobeniusAutomorphism(currentTerm)
		result = result.Add(currentTerm)
		currentDegree = saferithUtils.NatInc(currentDegree)
	}
	return result
}

func (*BaseFieldG2) FieldBytes() int {
	return bimpl.FieldBytesFp2
}

func (*BaseFieldG2) WideFieldBytes() int {
	return bimpl.WideFieldBytesFp2
}

// === Zp Methods.

func (*BaseFieldG2) New(v uint64) curves.BaseFieldElement {
	return NewBaseFieldElementG2(v)
}

func (f *BaseFieldG2) Zero() curves.BaseFieldElement {
	return f.AdditiveIdentity()
}

func (f *BaseFieldG2) One() curves.BaseFieldElement {
	return f.MultiplicativeIdentity()
}

// === Ordering Methods.

func (f *BaseFieldG2) Top() curves.BaseFieldElement {
	return f.Zero().Sub(f.One())
}

func (f *BaseFieldG2) Bottom() curves.BaseFieldElement {
	return f.Zero()
}

func (*BaseFieldG2) Join(x, y curves.BaseFieldElement) curves.BaseFieldElement {
	return x.Join(y)
}

func (*BaseFieldG2) Meet(x, y curves.BaseFieldElement) curves.BaseFieldElement {
	return x.Meet(y)
}

func (*BaseFieldG2) Max(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) curves.BaseFieldElement {
	max := x
	for _, y := range ys {
		max = max.Max(y)
	}
	return max
}

func (*BaseFieldG2) Min(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) curves.BaseFieldElement {
	min := x
	for _, y := range ys {
		min = min.Min(y)
	}
	return min
}
