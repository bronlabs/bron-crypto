package kuiper

import (
	bimpl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/arithmetic/limb7"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/kuiper/impl/fp"
	"io"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

var (
	plutoBaseFieldInitOnce sync.Once
	plutoBaseField         *PlutoBaseField

	// TODO:
	plutoBaseFieldOrder = saferith.ModulusFromUint64(1)
	//plutoBaseFieldOrder    = saferith.ModulusFromNat(saferithUtils.NatDec(p.Nat()))
)

var _ curves.BaseField = (*PlutoBaseField)(nil)

type PlutoBaseField struct {
	_ ds.Incomparable
}

func PlutoBaseFieldInit() {
	plutoBaseField = &PlutoBaseField{}
}

func NewPlutoBaseField() *PlutoBaseField {
	plutoBaseFieldInitOnce.Do(PlutoBaseFieldInit)
	return plutoBaseField
}

func (*PlutoBaseField) Curve() curves.Curve {
	return NewG1()
}

func (*PlutoBaseField) Cardinality() *saferith.Modulus {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) Contains(e curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) Iter() <-chan curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) Operators() []algebra.BinaryOperator[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (f *PlutoBaseField) Unwrap() curves.BaseField {
	return f
}

func (*PlutoBaseField) IsDefinedUnder(operator algebra.BinaryOperator[curves.BaseFieldElement]) bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) Op(operator algebra.BinaryOperator[curves.BaseFieldElement], x algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) Addition() algebra.Addition[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) Exp(base, power curves.BaseFieldElement) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) SimExp(bases []algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], exponents []*saferith.Nat) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) MultiBaseExp(bases []algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], exponent *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) MultiExponentExp(base algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], exponents []*saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) Multiplication() algebra.Multiplication[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) DiscreteExponentiation() algebra.DiscreteExponentiation[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) Identity(under algebra.BinaryOperator[curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) CoPrime(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) GCD(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) LCM(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) MultiplicativeGroup() algebra.MultiplicativeGroup[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) AlgebraicVariety() algebra.AlgebraicVariety[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) LatticeElement() algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) ChainElement() algebra.ChainElement[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) And(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) ConjunctiveIdentity() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) Or(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) DisjunctiveIdentity() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) ExclusiveDisjunctiveIdentity() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) ElementSize() int {
	return limb7.FieldBytes
}

func (*PlutoBaseField) WideElementSize() int {
	return limb7.WideFieldBytes
}

func (*PlutoBaseField) IsDecomposable(coprimeIdealNorms ...algebra.IntegerRingElement[curves.BaseField, curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) BaseFieldElement() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseField) Name() string {
	return NameG1
}

func (*PlutoBaseField) Order() *saferith.Modulus {
	return plutoBaseFieldOrder
}

func (f *PlutoBaseField) Element() curves.BaseFieldElement {
	return f.AdditiveIdentity()
}

func (f *PlutoBaseField) Random(prng io.Reader) (curves.BaseFieldElement, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	result, err := f.Element().(*PlutoBaseFieldElement).V.Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not generate random field element")
	}
	return &PlutoBaseFieldElement{V: result}, nil
}

func (*PlutoBaseField) Hash(x []byte) (curves.BaseFieldElement, error) {
	els, err := NewG1().HashToFieldElements(1, x, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not hash to field element in bls12381 G1")
	}
	return els[0], nil
}

func (*PlutoBaseField) Select(choice bool, x0, x1 curves.BaseFieldElement) curves.BaseFieldElement {
	x0p, ok0 := x0.(*PlutoBaseFieldElement)
	x1p, ok1 := x1.(*PlutoBaseFieldElement)
	if !ok0 || !ok1 {
		panic("Not a BLS12381 G1 field element")
	}
	return &PlutoBaseFieldElement{
		V: fp.NewFp().CMove(x0p.V, x1p.V, utils.BoolTo[uint64](choice)),
	}
}

// === Additive Groupoid Methods.

func (*PlutoBaseField) Add(x algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Multiplicative Groupoid Methods.

func (*PlutoBaseField) Mul(x algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	prod := x
	for _, y := range ys {
		prod = prod.Mul(y)
	}
	return prod.Unwrap()
}

// === Additive Monoid Methods.

func (*PlutoBaseField) AdditiveIdentity() curves.BaseFieldElement {
	return &PlutoBaseFieldElement{
		V: fp.NewFp().SetZero(),
	}
}

// === Multiplicative Monoid Methods.

func (*PlutoBaseField) MultiplicativeIdentity() curves.BaseFieldElement {
	return &PlutoBaseFieldElement{
		V: fp.NewFp().SetOne(),
	}
}

// === Additive Group Methods.

func (*PlutoBaseField) Sub(x algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	diff := x
	for _, y := range ys {
		diff = diff.Sub(y)
	}
	return diff.Unwrap()
}

// === Multiplicative Group Methods.

func (*PlutoBaseField) Div(x algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
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

func (*PlutoBaseField) QuadraticResidue(p algebra.RingElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	pp, ok := p.(*PlutoBaseFieldElement)
	if !ok {
		return nil, errs.NewType("given point is not from this field")
	}
	return pp.Sqrt()
}

// === Finite Field Methods.

func (f *PlutoBaseField) Characteristic() *saferith.Nat {
	return f.Order().Nat()
}

func (*PlutoBaseField) ExtensionDegree() *saferith.Nat {
	return saferithUtils.NatOne
}

func (f *PlutoBaseField) FrobeniusAutomorphism(e curves.BaseFieldElement) curves.BaseFieldElement {
	return e.Exp(f.Characteristic())
}

func (f *PlutoBaseField) Trace(e curves.BaseFieldElement) curves.BaseFieldElement {
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

func (*PlutoBaseField) FieldBytes() int {
	return bimpl.FieldBytes
}

func (*PlutoBaseField) WideFieldBytes() int {
	return bimpl.WideFieldBytes
}

// === Zp Methods.

func (*PlutoBaseField) New(v uint64) curves.BaseFieldElement {
	return NewPlutoBaseFieldElement(v)
}

func (f *PlutoBaseField) Zero() curves.BaseFieldElement {
	return f.AdditiveIdentity()
}

func (f *PlutoBaseField) One() curves.BaseFieldElement {
	return f.MultiplicativeIdentity()
}

// === Ordering Methods.

func (f *PlutoBaseField) Top() curves.BaseFieldElement {
	return f.Zero().Sub(f.One())
}

func (f *PlutoBaseField) Bottom() curves.BaseFieldElement {
	return f.Zero()
}

func (*PlutoBaseField) Join(x, y algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return x.Join(y)
}

func (*PlutoBaseField) Meet(x, y algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return x.Meet(y)
}

func (*PlutoBaseField) Max(x algebra.ChainElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ChainElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	theMax := x
	for _, y := range ys {
		theMax = theMax.Max(y.Unwrap())
	}
	return theMax.Unwrap()
}

func (*PlutoBaseField) Min(x algebra.ChainElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ChainElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	theMin := x
	for _, y := range ys {
		theMin = theMin.Min(y.Unwrap())
	}
	return theMin.Unwrap()
}
