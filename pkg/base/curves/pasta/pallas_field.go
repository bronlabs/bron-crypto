package pasta

import (
	"encoding/binary"
	"io"
	"iter"
	"slices"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base/algebra"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	pastaImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/pasta/impl"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	saferithUtils "github.com/bronlabs/krypton-primitives/pkg/base/utils/saferith"
)

var (
	pallasBaseFieldInitOnce sync.Once
	pallasBaseFieldInstance PallasBaseField
	pallasBaseFieldModulus  *saferith.Modulus
)

var _ curves.BaseField = (*PallasBaseField)(nil)

type PallasBaseField struct {
	_ ds.Incomparable
}

func pallasBaseFieldInit() {
	var modulusBytes [8 * pastaImpl.FpSatLimbs]byte
	for i, l := range pastaImpl.FpModulus {
		binary.LittleEndian.PutUint64(modulusBytes[i*8:(i+1)*8], l)
	}
	slices.Reverse(modulusBytes[:])
	pallasBaseFieldModulus = saferith.ModulusFromBytes(modulusBytes[:])

	pallasBaseFieldInstance = PallasBaseField{}
}

func NewPallasBaseField() *PallasBaseField {
	pallasBaseFieldInitOnce.Do(pallasBaseFieldInit)
	return &pallasBaseFieldInstance
}

func (*PallasBaseField) Curve() curves.Curve {
	return NewPallasCurve()
}

func (*PallasBaseField) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) Contains(e curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) Iter() iter.Seq[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) Operators() []algebra.BinaryOperator[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (f *PallasBaseField) Unwrap() curves.BaseField {
	return f
}

func (*PallasBaseField) IsDefinedUnder(operator algebra.BinaryOperator[curves.BaseFieldElement]) bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) Op(operator algebra.BinaryOperator[curves.BaseFieldElement], x algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) Addition() algebra.Addition[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) Exp(b, power curves.BaseFieldElement) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) SimExp(bases []algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], exponents []*saferith.Nat) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) MultiBaseExp(bases []algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], exponent *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) MultiExponentExp(b algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], exponents []*saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) Multiplication() algebra.Multiplication[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) DiscreteExponentiation() algebra.DiscreteExponentiation[curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) Identity(under algebra.BinaryOperator[curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) CoPrime(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) GCD(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) LCM(x curves.BaseFieldElement, ys ...curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) MultiplicativeGroup() algebra.MultiplicativeGroup[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) AlgebraicVariety() algebra.AlgebraicVariety[curves.Curve, curves.BaseField, curves.Point, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) LatticeElement() algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) ChainElement() algebra.ChainElement[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) And(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) ConjunctiveIdentity() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) Or(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) DisjunctiveIdentity() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) ExclusiveDisjunctiveIdentity() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseField) ElementSize() int {
	return pastaImpl.FpBytes
}

func (*PallasBaseField) WideElementSize() int {
	return pastaImpl.FpWideBytes
}

func (*PallasBaseField) IsDecomposable(coprimeIdealNorms ...algebra.IntegerRingElement[curves.BaseField, curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (f *PallasBaseField) BaseFieldElement() curves.BaseFieldElement {
	return f.Element()
}

func (*PallasBaseField) Name() string {
	return PallasName
}

func (*PallasBaseField) Order() *saferith.Modulus {
	panic("implement me")
}

func (f *PallasBaseField) Element() curves.BaseFieldElement {
	return f.AdditiveIdentity()
}

func (*PallasBaseField) Random(prng io.Reader) (curves.BaseFieldElement, error) {
	result := new(PallasBaseFieldElement)
	ok := result.V.SetRandom(prng)
	if ok != 1 {
		return nil, errs.NewRandomSample("pallas base field element")
	}

	return result, nil
}

func (*PallasBaseField) Hash(x []byte) (curves.BaseFieldElement, error) {
	panic("implement me")
}

func (*PallasBaseField) Select(choice uint64, x0, x1 curves.BaseFieldElement) curves.BaseFieldElement {
	x0f, ok0 := x0.(*PallasBaseFieldElement)
	if !ok0 {
		panic("x0 is not a non-empty pallas field element")
	}
	x1f, ok1 := x1.(*PallasBaseFieldElement)
	if !ok1 {
		panic("x1 is not a non-empty pallas field element")
	}

	result := new(PallasBaseFieldElement)
	result.V.Select(choice, &x0f.V, &x1f.V)
	return result
}

// === Additive Groupoid Methods.

func (*PallasBaseField) Add(x algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Multiplicative Groupoid Methods.

func (*PallasBaseField) Mul(x algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	prod := x
	for _, y := range ys {
		prod = prod.Mul(y)
	}
	return prod.Unwrap()
}

// === Additive Monoid Methods.

func (*PallasBaseField) AdditiveIdentity() curves.BaseFieldElement {
	result := new(PallasBaseFieldElement)
	result.V.SetZero()
	return result
}

// === Multiplicative Monoid Methods.

func (*PallasBaseField) MultiplicativeIdentity() curves.BaseFieldElement {
	result := new(PallasBaseFieldElement)
	result.V.SetOne()
	return result
}

// === Additive Group Methods.

func (*PallasBaseField) Sub(x algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	diff := x
	for _, y := range ys {
		diff = diff.Sub(y)
	}
	return diff.Unwrap()
}

// === Multiplicative Group Methods.

func (*PallasBaseField) Div(x algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
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

func (*PallasBaseField) Sqrt(p algebra.RingElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	pp, ok := p.(*PallasBaseFieldElement)
	if !ok {
		return nil, errs.NewType("given point is not from this field")
	}
	return pp.Sqrt()
}

// === Finite Field Methods.

func (f *PallasBaseField) Characteristic() *saferith.Nat {
	return f.Order().Nat()
}

func (*PallasBaseField) ExtensionDegree() *saferith.Nat {
	return saferithUtils.NatOne
}

func (f *PallasBaseField) FrobeniusAutomorphism(e curves.BaseFieldElement) curves.BaseFieldElement {
	return e.Exp(f.Characteristic())
}

func (f *PallasBaseField) Trace(e curves.BaseFieldElement) curves.BaseFieldElement {
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

func (*PallasBaseField) FieldBytes() int {
	return pastaImpl.FpBytes
}

func (*PallasBaseField) WideFieldBytes() int {
	return pastaImpl.FpWideBytes
}

// === Zp Methods.

func (*PallasBaseField) New(v uint64) curves.BaseFieldElement {
	return NewPallasBaseFieldElement(v)
}

func (f *PallasBaseField) Zero() curves.BaseFieldElement {
	return f.AdditiveIdentity()
}

func (f *PallasBaseField) One() curves.BaseFieldElement {
	return f.MultiplicativeIdentity()
}

// === Ordering Methods.

func (f *PallasBaseField) Top() curves.BaseFieldElement {
	return f.Zero().Sub(f.One())
}

func (f *PallasBaseField) Bottom() curves.BaseFieldElement {
	return f.Zero()
}

func (*PallasBaseField) Join(x, y algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return x.Join(y)
}

func (*PallasBaseField) Meet(x, y algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return x.Meet(y)
}

func (*PallasBaseField) Max(x algebra.ChainElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ChainElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	theMax := x
	for _, y := range ys {
		theMax = theMax.Max(y.Unwrap())
	}
	return theMax.Unwrap()
}

func (*PallasBaseField) Min(x algebra.ChainElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ChainElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	theMin := x
	for _, y := range ys {
		theMin = theMin.Min(y.Unwrap())
	}
	return theMin.Unwrap()
}
