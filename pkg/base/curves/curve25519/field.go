package curve25519

import (
	"crypto/subtle"
	"io"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

var (
	_                           curves.BaseField = (*BaseField)(nil)
	curve25519BaseFieldInitOnce sync.Once
	curve25519BaseFieldInstance BaseField
)

type BaseField struct {
	_ ds.Incomparable
}

func curve25519BaseFieldInit() {
	curve25519BaseFieldInstance = BaseField{}
}

func NewBaseField() *BaseField {
	curve25519BaseFieldInitOnce.Do(curve25519BaseFieldInit)
	return &curve25519BaseFieldInstance
}

func (*BaseField) Curve() curves.Curve {
	return NewCurve()
}

func (*BaseField) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) Contains(e curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) Iter() <-chan curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) Operators() []algebra.BinaryOperator[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (f *BaseField) Unwrap() curves.BaseField {
	return f
}

func (*BaseField) IsDefinedUnder(operator algebra.BinaryOperator[curves.BaseFieldElement]) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) Op(operator algebra.BinaryOperator[curves.BaseFieldElement], x algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) Addition() algebra.Addition[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) Exp(b, power curves.BaseFieldElement) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) SimExp(bases []algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], exponents []*saferith.Nat) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) MultiBaseExp(bases []algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], exponent *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) MultiExponentExp(b algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], exponents []*saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) Multiplication() algebra.Multiplication[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) DiscreteExponentiation() algebra.DiscreteExponentiation[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) Identity(under algebra.BinaryOperator[curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) CoPrime(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) GCD(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) LCM(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) MultiplicativeGroup() algebra.MultiplicativeGroup[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) AlgebraicVariety() algebra.AlgebraicVariety[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) LatticeElement() algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) ChainElement() algebra.ChainElement[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) And(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) ConjunctiveIdentity() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) Or(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) DisjunctiveIdentity() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) ExclusiveDisjunctiveIdentity() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) ElementSize() int {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) WideElementSize() int {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) IsDecomposable(coprimeIdealNorms ...algebra.IntegerRingElement[curves.BaseField, curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) BaseFieldElement() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseField) Name() string {
	return Name
}

func (*BaseField) Order() *saferith.Modulus {
	return baseFieldOrder
}

func (f *BaseField) Element() curves.BaseFieldElement {
	return f.AdditiveIdentity()
}

func (*BaseField) Hash(x []byte) (curves.BaseFieldElement, error) {
	els, err := NewCurve().HashToFieldElements(1, x, nil)
	if err != nil {
		return nil, errs.WrapHashing(err, "could not hash to field element in edwards25519")
	}
	return els[0], nil
}

func (*BaseField) Random(prng io.Reader) (curves.BaseFieldElement, error) {
	panic("not implemented")
}

func (*BaseField) Select(choice bool, x0, x1 curves.BaseFieldElement) curves.BaseFieldElement {
	xFp, ok1 := x0.(*BaseFieldElement)
	yFp, ok2 := x1.(*BaseFieldElement)
	if !ok1 || !ok2 {
		panic("Not a BLS12381 G1 field element")
	}
	sFp := new(BaseFieldElement)
	copy(sFp.V[:], xFp.V[:])
	subtle.ConstantTimeCopy(utils.BoolTo[int](choice), xFp.V[:], yFp.V[:])
	return sFp
}

// === Additive Groupoid Methods.

func (*BaseField) Add(x algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Multiplicative Groupoid Methods.

func (*BaseField) Mul(x algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	prod := x
	for _, y := range ys {
		prod = prod.Mul(y)
	}
	return prod.Unwrap()
}

// === Additive Monoid Methods.

func (*BaseField) AdditiveIdentity() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: [32]byte{},
	}
}

// === Multiplicative Monoid Methods.

func (*BaseField) MultiplicativeIdentity() curves.BaseFieldElement {
	panic("not implemented")
}

// === Additive Group Methods.

func (*BaseField) Sub(x algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	diff := x
	for _, y := range ys {
		diff = diff.Sub(y)
	}
	return diff.Unwrap()
}

// === Multiplicative Group Methods.

func (*BaseField) Div(x algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	result := x
	for _, y := range ys {
		var err error
		result, err = result.Div(y)
		if err != nil {
			return nil, errs.WrapFailed(err, "division failed")
		}
	}
	return result.Unwrap(), nil
}

// === Ring Methods.

func (*BaseField) QuadraticResidue(p algebra.RingElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	pp, ok := p.(*BaseFieldElement)
	if !ok {
		return nil, errs.NewType("given point is not from this field")
	}
	return pp.Sqrt()
}

// === Finite Field Methods.

func (f *BaseField) Characteristic() *saferith.Nat {
	return f.Order().Nat()
}

func (*BaseField) ExtensionDegree() *saferith.Nat {
	return saferithUtils.NatOne
}

func (f *BaseField) FrobeniusAutomorphism(e curves.BaseFieldElement) curves.BaseFieldElement {
	return e.Exp(f.Characteristic())
}

func (f *BaseField) Trace(e curves.BaseFieldElement) curves.BaseFieldElement {
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

func (*BaseField) Join(x, y algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return x.Join(y)
}

func (*BaseField) Meet(x, y algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return x.Meet(y)
}

func (*BaseField) Max(x algebra.ChainElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ChainElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	theMax := x
	for _, y := range ys {
		theMax = theMax.Max(y.Unwrap())
	}
	return theMax.Unwrap()
}

func (*BaseField) Min(x algebra.ChainElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ChainElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	theMin := x
	for _, y := range ys {
		theMin = theMin.Min(y.Unwrap())
	}
	return theMin.Unwrap()
}
