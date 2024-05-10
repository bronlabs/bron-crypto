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
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
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

func (*BaseFieldG2) Cardinality() *saferith.Modulus {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) Contains(e curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) Iter() <-chan curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) Operators() []algebra.BinaryOperator[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (f *BaseFieldG2) Unwrap() curves.BaseField {
	return f
}

func (*BaseFieldG2) IsDefinedUnder(operator algebra.BinaryOperator[curves.BaseFieldElement]) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) Op(operator algebra.BinaryOperator[curves.BaseFieldElement], x algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) Addition() algebra.Addition[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) Exp(base, power curves.BaseFieldElement) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) SimExp(bases []algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], exponents []*saferith.Nat) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) MultiBaseExp(bases []algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], exponent *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) MultiExponentExp(base algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], exponents []*saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) Multiplication() algebra.Multiplication[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) DiscreteExponentiation() algebra.DiscreteExponentiation[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) Identity(under algebra.BinaryOperator[curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) CoPrime(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) GCD(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) LCM(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) MultiplicativeGroup() algebra.MultiplicativeGroup[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) AlgebraicVariety() algebra.AlgebraicVariety[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) LatticeElement() algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) ChainElement() algebra.ChainElement[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) And(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) ConjunctiveIdentity() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) Or(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) DisjunctiveIdentity() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) ExclusiveDisjunctiveIdentity() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) ElementSize() int {
	return 2 * 48
}

func (*BaseFieldG2) WideElementSize() int {
	return 2 * 2 * 48
}

func (*BaseFieldG2) IsDecomposable(coprimeIdealNorms ...integer.Uint[curves.BaseField, curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) BaseFieldElement() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldG2) Name() string {
	return NameG2
}

func (*BaseFieldG2) Order() *saferith.Modulus {
	return saferith.ModulusFromNat(p2)
}

func (f *BaseFieldG2) Element() curves.BaseFieldElement {
	return f.AdditiveIdentity()
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

func (*BaseFieldG2) Add(x algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Multiplicative Groupoid Methods.

func (*BaseFieldG2) Mul(x algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	prod := x
	for _, y := range ys {
		prod = prod.Mul(y)
	}
	return prod.Unwrap()
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

func (*BaseFieldG2) Sub(x algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	diff := x
	for _, y := range ys {
		diff = diff.Sub(y)
	}
	return diff.Unwrap()
}

// === Multiplicative Group Methods.

func (*BaseFieldG2) Div(x algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
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

func (*BaseFieldG2) QuadraticResidue(p algebra.RingElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
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
	return e.Exp(f.Characteristic())
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

func (*BaseFieldG2) Join(x, y algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return x.Join(y)
}

func (*BaseFieldG2) Meet(x, y algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return x.Meet(y)
}

func (*BaseFieldG2) Max(x algebra.ChainElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ChainElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	theMax := x
	for _, y := range ys {
		theMax = theMax.Max(y.Unwrap())
	}
	return theMax.Unwrap()
}

func (*BaseFieldG2) Min(x algebra.ChainElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ChainElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	theMin := x
	for _, y := range ys {
		theMin = theMin.Min(y.Unwrap())
	}
	return theMin.Unwrap()
}
