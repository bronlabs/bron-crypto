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
	g1BaseFieldInitOnce sync.Once
	g1BaseFieldInstance BaseFieldG1
)

var (
	g1BaseFieldOrder = saferith.ModulusFromNat(saferithUtils.NatDec(p.Nat()))
)

var _ curves.BaseField = (*BaseFieldG1)(nil)

type BaseFieldG1 struct {
	_ ds.Incomparable
}

func g1BaseFieldInit() {
	g1BaseFieldInstance = BaseFieldG1{}
}

func NewBaseFieldG1() *BaseFieldG1 {
	g1BaseFieldInitOnce.Do(g1BaseFieldInit)
	return &g1BaseFieldInstance
}

func (*BaseFieldG1) Curve() curves.Curve {
	return NewG1()
}

func (*BaseFieldG1) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) Contains(e curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) Iterator() ds.Iterator[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) Operators() []algebra.BinaryOperator[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (f *BaseFieldG1) Unwrap() curves.BaseField {
	return f
}

func (*BaseFieldG1) IsDefinedUnder(operator algebra.BinaryOperator[curves.BaseFieldElement]) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) Op(operator algebra.BinaryOperator[curves.BaseFieldElement], x algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) Addition() algebra.Addition[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) Exp(base, power curves.BaseFieldElement) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) SimExp(bases []algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], exponents []*saferith.Nat) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) MultiBaseExp(bases []algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], exponent *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) MultiExponentExp(base algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], exponents []*saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) Multiplication() algebra.Multiplication[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) DiscreteExponentiation() algebra.DiscreteExponentiation[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) Identity(under algebra.BinaryOperator[curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) CoPrime(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) GCD(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) LCM(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) MultiplicativeGroup() algebra.MultiplicativeGroup[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) AlgebraicVariety() algebra.AlgebraicVariety[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) LatticeElement() algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) ChainElement() algebra.ChainElement[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) And(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) ConjunctiveIdentity() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) Or(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) DisjunctiveIdentity() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) ExclusiveDisjunctiveIdentity() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) ElementSize() int {
	return 48
}

func (*BaseFieldG1) WideElementSize() int {
	return 2 * 48
}

func (*BaseFieldG1) IsDecomposable(coprimeIdealNorms ...algebra.IntegerRingElement[curves.BaseField, curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) BaseFieldElement() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG1) Name() string {
	return NameG1
}

func (*BaseFieldG1) Order() *saferith.Modulus {
	return g1BaseFieldOrder
}

func (f *BaseFieldG1) Element() curves.BaseFieldElement {
	return f.AdditiveIdentity()
}

func (f *BaseFieldG1) Random(prng io.Reader) (curves.BaseFieldElement, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	result, err := f.Element().(*BaseFieldElementG1).V.Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not generate random field element")
	}
	return &BaseFieldElementG1{V: result}, nil
}

func (*BaseFieldG1) Hash(x []byte) (curves.BaseFieldElement, error) {
	els, err := NewG1().HashToFieldElements(1, x, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not hash to field element in bls12381 G1")
	}
	return els[0], nil
}

func (*BaseFieldG1) Select(choice bool, x0, x1 curves.BaseFieldElement) curves.BaseFieldElement {
	x0p, ok0 := x0.(*BaseFieldElementG1)
	x1p, ok1 := x1.(*BaseFieldElementG1)
	if !ok0 || !ok1 {
		panic("Not a BLS12381 G1 field element")
	}
	return &BaseFieldElementG1{
		V: new(bimpl.Fp).CMove(x0p.V, x1p.V, utils.BoolTo[int](choice)),
	}
}

// === Additive Groupoid Methods.

func (*BaseFieldG1) Add(x algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Multiplicative Groupoid Methods.

func (*BaseFieldG1) Mul(x algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	prod := x
	for _, y := range ys {
		prod = prod.Mul(y)
	}
	return prod.Unwrap()
}

// === Additive Monoid Methods.

func (*BaseFieldG1) AdditiveIdentity() curves.BaseFieldElement {
	return &BaseFieldElementG1{
		V: new(bimpl.Fp).SetZero(),
	}
}

// === Multiplicative Monoid Methods.

func (*BaseFieldG1) MultiplicativeIdentity() curves.BaseFieldElement {
	return &BaseFieldElementG1{
		V: new(bimpl.Fp).SetOne(),
	}
}

// === Additive Group Methods.

func (*BaseFieldG1) Sub(x algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	diff := x
	for _, y := range ys {
		diff = diff.Sub(y)
	}
	return diff.Unwrap()
}

// === Multiplicative Group Methods.

func (*BaseFieldG1) Div(x algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	result := x
	for _, y := range ys {
		var err error
		result, err = result.Div(y)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not divide field elements")
		}
	}
	return result.Unwrap(), nil
}

// === Ring Methods.

func (*BaseFieldG1) QuadraticResidue(p algebra.RingElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	pp, ok := p.(*BaseFieldElementG1)
	if !ok {
		return nil, errs.NewType("given point is not from this field")
	}
	return pp.Sqrt()
}

// === Finite Field Methods.

func (f *BaseFieldG1) Characteristic() *saferith.Nat {
	return f.Order().Nat()
}

func (*BaseFieldG1) ExtensionDegree() *saferith.Nat {
	return saferithUtils.NatOne
}

func (f *BaseFieldG1) FrobeniusAutomorphism(e curves.BaseFieldElement) curves.BaseFieldElement {
	return e.Exp(f.Characteristic())
}

func (f *BaseFieldG1) Trace(e curves.BaseFieldElement) curves.BaseFieldElement {
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

func (*BaseFieldG1) FieldBytes() int {
	return bimpl.FieldBytes
}

func (*BaseFieldG1) WideFieldBytes() int {
	return bimpl.WideFieldBytes
}

// === Zp Methods.

func (*BaseFieldG1) New(v uint64) curves.BaseFieldElement {
	return NewBaseFieldElementG1(v)
}

func (f *BaseFieldG1) Zero() curves.BaseFieldElement {
	return f.AdditiveIdentity()
}

func (f *BaseFieldG1) One() curves.BaseFieldElement {
	return f.MultiplicativeIdentity()
}

// === Ordering Methods.

func (f *BaseFieldG1) Top() curves.BaseFieldElement {
	return f.Zero().Sub(f.One())
}

func (f *BaseFieldG1) Bottom() curves.BaseFieldElement {
	return f.Zero()
}

func (*BaseFieldG1) Join(x, y algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return x.Join(y)
}

func (*BaseFieldG1) Meet(x, y algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return x.Meet(y)
}

func (*BaseFieldG1) Max(x algebra.ChainElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ChainElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	theMax := x
	for _, y := range ys {
		theMax = theMax.Max(y.Unwrap())
	}
	return theMax.Unwrap()
}

func (*BaseFieldG1) Min(x algebra.ChainElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ChainElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	theMin := x
	for _, y := range ys {
		theMin = theMin.Min(y.Unwrap())
	}
	return theMin.Unwrap()
}
