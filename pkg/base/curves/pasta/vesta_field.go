package pasta

import (
	"io"
	"iter"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base/algebra"
	"github.com/bronlabs/krypton-primitives/pkg/base/bitstring"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	pastaImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/pasta/impl"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	saferithUtils "github.com/bronlabs/krypton-primitives/pkg/base/utils/saferith"
)

var (
	vestaBaseFieldInitOnce sync.Once
	vestaBaseFieldInstance VestaBaseField
	vestaBaseFieldModulus  *saferith.Modulus
)

var _ curves.BaseField = (*VestaBaseField)(nil)

type VestaBaseField struct {
	_ ds.Incomparable
}

func vestaBaseFieldInit() {
	vestaBaseFieldModulus = saferith.ModulusFromBytes(bitstring.ReverseBytes(pastaImpl.FqModulus[:]))

	vestaBaseFieldInstance = VestaBaseField{}
}

func NewVestaBaseField() *VestaBaseField {
	vestaBaseFieldInitOnce.Do(vestaBaseFieldInit)
	return &vestaBaseFieldInstance
}

func (*VestaBaseField) Curve() curves.Curve {
	return NewVestaCurve()
}

func (*VestaBaseField) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) Contains(e curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) Iter() iter.Seq[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) Operators() []algebra.BinaryOperator[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (f *VestaBaseField) Unwrap() curves.BaseField {
	return f
}

func (*VestaBaseField) IsDefinedUnder(operator algebra.BinaryOperator[curves.BaseFieldElement]) bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) Op(operator algebra.BinaryOperator[curves.BaseFieldElement], x algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) Addition() algebra.Addition[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) Exp(b, power curves.BaseFieldElement) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) SimExp(bases []algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], exponents []*saferith.Nat) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) MultiBaseExp(bases []algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], exponent *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) MultiExponentExp(b algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], exponents []*saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) Multiplication() algebra.Multiplication[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) DiscreteExponentiation() algebra.DiscreteExponentiation[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) Identity(under algebra.BinaryOperator[curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) CoPrime(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) GCD(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) LCM(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) MultiplicativeGroup() algebra.MultiplicativeGroup[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) AlgebraicVariety() algebra.AlgebraicVariety[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) LatticeElement() algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) ChainElement() algebra.ChainElement[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) And(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) ConjunctiveIdentity() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) Or(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) DisjunctiveIdentity() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) ExclusiveDisjunctiveIdentity() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseField) ElementSize() int {
	return pastaImpl.FqBytes
}

func (*VestaBaseField) WideElementSize() int {
	return pastaImpl.FqWideBytes
}

func (*VestaBaseField) IsDecomposable(coprimeIdealNorms ...algebra.IntegerRingElement[curves.BaseField, curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (f *VestaBaseField) BaseFieldElement() curves.BaseFieldElement {
	return f.Element()
}

func (*VestaBaseField) Name() string {
	return VestaName
}

func (*VestaBaseField) Order() *saferith.Modulus {
	panic("implement me")
}

func (f *VestaBaseField) Element() curves.BaseFieldElement {
	return f.AdditiveIdentity()
}

func (*VestaBaseField) Random(prng io.Reader) (curves.BaseFieldElement, error) {
	result := new(VestaBaseFieldElement)
	ok := result.V.SetRandom(prng)
	if ok != 1 {
		return nil, errs.NewRandomSample("vesta base field element")
	}

	return result, nil
}

func (*VestaBaseField) Hash(x []byte) (curves.BaseFieldElement, error) {
	panic("implement me")
}

func (*VestaBaseField) Select(choice uint64, x0, x1 curves.BaseFieldElement) curves.BaseFieldElement {
	x0f, ok0 := x0.(*VestaBaseFieldElement)
	if !ok0 {
		panic("x0 is not a non-empty vesta field element")
	}
	x1f, ok1 := x1.(*VestaBaseFieldElement)
	if !ok1 {
		panic("x1 is not a non-empty vesta field element")
	}

	result := new(VestaBaseFieldElement)
	result.V.Select(choice, &x0f.V, &x1f.V)
	return result
}

// === Additive Groupoid Methods.

func (*VestaBaseField) Add(x algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Multiplicative Groupoid Methods.

func (*VestaBaseField) Mul(x algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	prod := x
	for _, y := range ys {
		prod = prod.Mul(y)
	}
	return prod.Unwrap()
}

// === Additive Monoid Methods.

func (*VestaBaseField) AdditiveIdentity() curves.BaseFieldElement {
	result := new(VestaBaseFieldElement)
	result.V.SetZero()
	return result
}

// === Multiplicative Monoid Methods.

func (*VestaBaseField) MultiplicativeIdentity() curves.BaseFieldElement {
	result := new(VestaBaseFieldElement)
	result.V.SetOne()
	return result
}

// === Additive Group Methods.

func (*VestaBaseField) Sub(x algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	diff := x
	for _, y := range ys {
		diff = diff.Sub(y)
	}
	return diff.Unwrap()
}

// === Multiplicative Group Methods.

func (*VestaBaseField) Div(x algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	result := x
	for _, y := range ys {
		var err error
		result, err = result.Div(y)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not divide field element")
		}
	}

	return result.Unwrap(), nil
}

// === Ring Methods.

func (*VestaBaseField) Sqrt(p algebra.RingElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	pp, ok := p.(*VestaBaseFieldElement)
	if !ok {
		return nil, errs.NewType("given point is not from this field")
	}
	return pp.Sqrt()
}

// === Finite Field Methods.

func (f *VestaBaseField) Characteristic() *saferith.Nat {
	return f.Order().Nat()
}

func (*VestaBaseField) ExtensionDegree() *saferith.Nat {
	return saferithUtils.NatOne
}

func (f *VestaBaseField) FrobeniusAutomorphism(e curves.BaseFieldElement) curves.BaseFieldElement {
	return e.Exp(f.Characteristic())
}

func (f *VestaBaseField) Trace(e curves.BaseFieldElement) curves.BaseFieldElement {
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

func (*VestaBaseField) FieldBytes() int {
	return pastaImpl.FqBytes
}

func (*VestaBaseField) WideFieldBytes() int {
	return pastaImpl.FqWideBytes
}

// === Zp Methods.

func (*VestaBaseField) New(v uint64) curves.BaseFieldElement {
	return NewVestaBaseFieldElement(v)
}

func (f *VestaBaseField) Zero() curves.BaseFieldElement {
	return f.AdditiveIdentity()
}

func (f *VestaBaseField) One() curves.BaseFieldElement {
	return f.MultiplicativeIdentity()
}

// === Ordering Methods.

func (f *VestaBaseField) Top() curves.BaseFieldElement {
	return f.Zero().Sub(f.One())
}

func (f *VestaBaseField) Bottom() curves.BaseFieldElement {
	return f.Zero()
}

func (*VestaBaseField) Join(x, y algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return x.Join(y)
}

func (*VestaBaseField) Meet(x, y algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return x.Meet(y)
}

func (*VestaBaseField) Max(x algebra.ChainElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ChainElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	theMax := x
	for _, y := range ys {
		theMax = theMax.Max(y.Unwrap())
	}
	return theMax.Unwrap()
}

func (*VestaBaseField) Min(x algebra.ChainElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ChainElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	theMin := x
	for _, y := range ys {
		theMin = theMin.Min(y.Unwrap())
	}
	return theMin.Unwrap()
}
