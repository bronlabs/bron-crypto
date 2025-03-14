package pasta

import (
	"io"
	"iter"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	pastaImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/pasta/impl"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	saferithUtils "github.com/bronlabs/bron-crypto/pkg/base/utils/saferith"
)

var (
	vestaScalarFieldInitOnce sync.Once
	vestaScalarFieldInstance VestaScalarField
)

var _ curves.ScalarField = (*VestaScalarField)(nil)

type VestaScalarField struct {
	_ ds.Incomparable
}

func vestaScalarFieldInit() {
	vestaScalarFieldInstance = VestaScalarField{}
}

func NewVestaScalarField() *VestaScalarField {
	vestaScalarFieldInitOnce.Do(vestaScalarFieldInit)
	return &vestaScalarFieldInstance
}

func (*VestaScalarField) Curve() curves.Curve {
	return NewVestaCurve()
}

func (*VestaScalarField) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) Contains(e curves.Scalar) bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) Iter() iter.Seq[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (sf *VestaScalarField) Unwrap() curves.ScalarField {
	return sf
}

func (*VestaScalarField) IsDefinedUnder(operator algebra.BinaryOperator[curves.Scalar]) bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) Op(operator algebra.BinaryOperator[curves.Scalar], x algebra.GroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.GroupoidElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) Addition() algebra.Addition[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) Exp(b curves.Scalar, power curves.Scalar) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) Operators() []algebra.BinaryOperator[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) SimExp(bases []algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], exponents []*saferith.Nat) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) MultiBaseExp(bases []algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], exponent *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) MultiExponentExp(b algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], exponents []*saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) Multiplication() algebra.Multiplication[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) DiscreteExponentiation() algebra.DiscreteExponentiation[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) Identity(under algebra.BinaryOperator[curves.Scalar]) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) CoPrime(x curves.Scalar, ys ...curves.Scalar) bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) GCD(x curves.Scalar, ys ...curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) LCM(x curves.Scalar, ys ...curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) MultiplicativeGroup() algebra.MultiplicativeGroup[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) VectorSpace() algebra.VectorSpace[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) LatticeElement() algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) ChainElement() algebra.ChainElement[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) And(x algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) ConjunctiveIdentity() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) Or(x algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) DisjunctiveIdentity() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) ExclusiveDisjunctiveIdentity() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalarField) ElementSize() int {
	return pastaImpl.FpBytes
}

func (*VestaScalarField) WideElementSize() int {
	return pastaImpl.FpWideBytes
}

func (*VestaScalarField) IsDecomposable(coprimeIdealNorms ...algebra.IntegerRingElement[curves.ScalarField, curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (sf *VestaScalarField) Scalar() curves.Scalar {
	return sf.Element()
}

func (*VestaScalarField) Name() string {
	return VestaName
}

func (*VestaScalarField) Order() *saferith.Modulus {
	return NewVestaCurve().SubGroupOrder()
}

func (sf *VestaScalarField) Element() curves.Scalar {
	return sf.AdditiveIdentity()
}

func (sf *VestaScalarField) Random(prng io.Reader) (curves.Scalar, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	var seed [pastaImpl.FpWideBytes]byte
	_, err := io.ReadFull(prng, seed[:])
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not read from reader")
	}
	value, err := sf.Element().SetBytesWide(seed[:])
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not set bytes")
	}
	return value, nil
}

func (*VestaScalarField) Hash(x []byte) (curves.Scalar, error) {
	u, err := NewVestaCurve().HashToScalars(1, base.Hash2CurveAppTag+VestaHash2CurveScalarSuite, x)
	if err != nil {
		return nil, errs.WrapHashing(err, "hash to scalar failed for vesta")
	}
	return u[0], nil
}

func (sf *VestaScalarField) Select(choice uint64, x0, x1 curves.Scalar) curves.Scalar {
	x0s, ok0 := x0.(*VestaScalar)
	if !ok0 {
		panic("x0 is not a non-empty vesta scalar")
	}
	x1s, ok1 := x1.(*VestaScalar)
	if !ok1 {
		panic("x1 is not a non-empty vesta scalar")
	}
	s, oks := sf.Element().(*VestaScalar)
	if !oks {
		panic("s is not a non-empty vesta scalar")
	}
	s.V.Select(choice, &x0s.V, &x1s.V)
	return s
}

// === Additive Groupoid Methods.

func (*VestaScalarField) Add(x algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Multiplicative Groupoid Methods.

func (*VestaScalarField) Mul(x algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	result := x
	for _, y := range ys {
		result = result.Mul(y)
	}
	return result.Unwrap()
}

// === Additive Monoid Methods.

func (*VestaScalarField) AdditiveIdentity() curves.Scalar {
	result := new(VestaScalar)
	result.V.SetZero()
	return result
}

// === Multiplicative Monoid Methods.

func (*VestaScalarField) MultiplicativeIdentity() curves.Scalar {
	result := new(VestaScalar)
	result.V.SetOne()
	return result
}

// === Additive Group Methods.

func (*VestaScalarField) Sub(x algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar], ys ...algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	result := x
	for _, y := range ys {
		result = result.Sub(y)
	}
	return result.Unwrap()
}

// === Multiplicative Group Methods.

func (*VestaScalarField) Div(x algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar], ys ...algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	result := x
	for _, y := range ys {
		var err error
		result, err = result.Div(y)
		if err != nil {
			return nil, errs.WrapFailed(err, "divide by zero")
		}
	}
	return result.Unwrap(), nil
}

// === Ring Methods.

func (*VestaScalarField) Sqrt(s algebra.RingElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	ss, ok := s.(*VestaScalar)
	if !ok {
		return nil, errs.NewType("given point is not from this field")
	}
	return ss.Sqrt()
}

// === Finite Field Methods.

func (sf *VestaScalarField) Characteristic() *saferith.Nat {
	return sf.Order().Nat()
}

func (*VestaScalarField) ExtensionDegree() *saferith.Nat {
	return saferithUtils.NatOne
}

func (sf *VestaScalarField) FrobeniusAutomorphism(e curves.Scalar) curves.Scalar {
	return e.Exp(sf.Characteristic())
}

func (sf *VestaScalarField) Trace(e curves.Scalar) curves.Scalar {
	result := e
	currentDegree := saferithUtils.NatOne
	currentTerm := result
	for currentDegree.Eq(sf.ExtensionDegree()) == 1 {
		currentTerm = sf.FrobeniusAutomorphism(currentTerm)
		result = result.Add(currentTerm)
		currentDegree = saferithUtils.NatInc(currentDegree)
	}
	return result
}

func (*VestaScalarField) FieldBytes() int {
	return pastaImpl.FpBytes
}

func (*VestaScalarField) WideFieldBytes() int {
	return pastaImpl.FpWideBytes
}

// === Zp Methods.

func (*VestaScalarField) New(value uint64) curves.Scalar {
	return NewVestaScalar(value)
}

func (sf *VestaScalarField) Zero() curves.Scalar {
	return sf.AdditiveIdentity()
}

func (sf *VestaScalarField) One() curves.Scalar {
	return sf.MultiplicativeIdentity()
}

// === Ordering Methods.

func (sf *VestaScalarField) Top() curves.Scalar {
	return sf.Zero().Sub(sf.One())
}

func (sf *VestaScalarField) Bottom() curves.Scalar {
	return sf.Zero()
}

func (*VestaScalarField) Join(x algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar], y algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return x.Join(y)
}

func (*VestaScalarField) Meet(x algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar], y algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return x.Meet(y)
}

func (*VestaScalarField) Max(x algebra.ChainElement[curves.ScalarField, curves.Scalar], ys ...algebra.ChainElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	theMax := x
	for _, y := range ys {
		theMax = theMax.Max(y.Unwrap())
	}
	return theMax.Unwrap()
}

func (*VestaScalarField) Min(x algebra.ChainElement[curves.ScalarField, curves.Scalar], ys ...algebra.ChainElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	theMin := x
	for _, y := range ys {
		theMin = theMin.Min(y.Unwrap())
	}
	return theMin.Unwrap()
}
