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
	pallasScalarFieldInitOnce sync.Once
	pallasScalarFieldInstance PallasScalarField
)

var _ curves.ScalarField = (*PallasScalarField)(nil)

type PallasScalarField struct {
	_ ds.Incomparable
}

func pallasScalarFieldInit() {
	pallasScalarFieldInstance = PallasScalarField{}
}

func NewPallasScalarField() *PallasScalarField {
	pallasScalarFieldInitOnce.Do(pallasScalarFieldInit)
	return &pallasScalarFieldInstance
}

func (*PallasScalarField) Curve() curves.Curve {
	return NewPallasCurve()
}

func (*PallasScalarField) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) Contains(e curves.Scalar) bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) Iter() iter.Seq[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (sf *PallasScalarField) Unwrap() curves.ScalarField {
	return sf
}

func (*PallasScalarField) IsDefinedUnder(operator algebra.BinaryOperator[curves.Scalar]) bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) Op(operator algebra.BinaryOperator[curves.Scalar], x algebra.GroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.GroupoidElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) Addition() algebra.Addition[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) Exp(b curves.Scalar, power curves.Scalar) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) Operators() []algebra.BinaryOperator[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) SimExp(bases []algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], exponents []*saferith.Nat) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) MultiBaseExp(bases []algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], exponent *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) MultiExponentExp(b algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], exponents []*saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) Multiplication() algebra.Multiplication[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) DiscreteExponentiation() algebra.DiscreteExponentiation[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) Identity(under algebra.BinaryOperator[curves.Scalar]) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) CoPrime(x curves.Scalar, ys ...curves.Scalar) bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) GCD(x curves.Scalar, ys ...curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) LCM(x curves.Scalar, ys ...curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) MultiplicativeGroup() algebra.MultiplicativeGroup[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) VectorSpace() algebra.VectorSpace[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) LatticeElement() algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) ChainElement() algebra.ChainElement[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) And(x algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) ConjunctiveIdentity() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) Or(x algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) DisjunctiveIdentity() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) ExclusiveDisjunctiveIdentity() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalarField) ElementSize() int {
	return pastaImpl.FqBytes
}

func (*PallasScalarField) WideElementSize() int {
	return pastaImpl.FqWideBytes
}

func (*PallasScalarField) IsDecomposable(coprimeIdealNorms ...algebra.IntegerRingElement[curves.ScalarField, curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (sf *PallasScalarField) Scalar() curves.Scalar {
	return sf.Element()
}

func (*PallasScalarField) Name() string {
	return PallasName
}

func (*PallasScalarField) Order() *saferith.Modulus {
	return NewPallasCurve().SubGroupOrder()
}

func (sf *PallasScalarField) Element() curves.Scalar {
	return sf.AdditiveIdentity()
}

func (sf *PallasScalarField) Random(prng io.Reader) (curves.Scalar, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	var seed [pastaImpl.FqWideBytes]byte
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

func (*PallasScalarField) Hash(x []byte) (curves.Scalar, error) {
	u, err := NewPallasCurve().HashToScalars(1, base.Hash2CurveAppTag+PallasHash2CurveScalarSuite, x)
	if err != nil {
		return nil, errs.WrapHashing(err, "hash to scalar failed for pallas")
	}
	return u[0], nil
}

func (sf *PallasScalarField) Select(choice uint64, x0, x1 curves.Scalar) curves.Scalar {
	x0s, ok0 := x0.(*PallasScalar)
	if !ok0 {
		panic("x0 is not a non-empty pallas scalar")
	}
	x1s, ok1 := x1.(*PallasScalar)
	if !ok1 {
		panic("x1 is not a non-empty pallas scalar")
	}
	s, oks := sf.Element().(*PallasScalar)
	if !oks {
		panic("s is not a non-empty pallas scalar")
	}
	s.V.Select(choice, &x0s.V, &x1s.V)
	return s
}

// === Additive Groupoid Methods.

func (*PallasScalarField) Add(x algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Multiplicative Groupoid Methods.

func (*PallasScalarField) Mul(x algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	result := x
	for _, y := range ys {
		result = result.Mul(y)
	}
	return result.Unwrap()
}

// === Additive Monoid Methods.

func (*PallasScalarField) AdditiveIdentity() curves.Scalar {
	result := new(PallasScalar)
	result.V.SetZero()
	return result
}

// === Multiplicative Monoid Methods.

func (*PallasScalarField) MultiplicativeIdentity() curves.Scalar {
	result := new(PallasScalar)
	result.V.SetOne()
	return result
}

// === Additive Group Methods.

func (*PallasScalarField) Sub(x algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar], ys ...algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	result := x
	for _, y := range ys {
		result = result.Sub(y)
	}
	return result.Unwrap()
}

// === Multiplicative Group Methods.

func (*PallasScalarField) Div(x algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar], ys ...algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
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

func (*PallasScalarField) Sqrt(s algebra.RingElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	ss, ok := s.(*PallasScalar)
	if !ok {
		return nil, errs.NewType("given point is not from this field")
	}
	return ss.Sqrt()
}

// === Finite Field Methods.

func (sf *PallasScalarField) Characteristic() *saferith.Nat {
	return sf.Order().Nat()
}

func (*PallasScalarField) ExtensionDegree() *saferith.Nat {
	return saferithUtils.NatOne
}

func (sf *PallasScalarField) FrobeniusAutomorphism(e curves.Scalar) curves.Scalar {
	return e.Exp(sf.Characteristic())
}

func (sf *PallasScalarField) Trace(e curves.Scalar) curves.Scalar {
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

func (*PallasScalarField) FieldBytes() int {
	return pastaImpl.FqBytes
}

func (*PallasScalarField) WideFieldBytes() int {
	return pastaImpl.FqWideBytes
}

// === Zp Methods.

func (*PallasScalarField) New(value uint64) curves.Scalar {
	return NewPallasScalar(value)
}

func (sf *PallasScalarField) Zero() curves.Scalar {
	return sf.AdditiveIdentity()
}

func (sf *PallasScalarField) One() curves.Scalar {
	return sf.MultiplicativeIdentity()
}

// === Ordering Methods.

func (sf *PallasScalarField) Top() curves.Scalar {
	return sf.Zero().Sub(sf.One())
}

func (sf *PallasScalarField) Bottom() curves.Scalar {
	return sf.Zero()
}

func (*PallasScalarField) Join(x algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar], y algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return x.Join(y)
}

func (*PallasScalarField) Meet(x algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar], y algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return x.Meet(y)
}

func (*PallasScalarField) Max(x algebra.ChainElement[curves.ScalarField, curves.Scalar], ys ...algebra.ChainElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	theMax := x
	for _, y := range ys {
		theMax = theMax.Max(y.Unwrap())
	}
	return theMax.Unwrap()
}

func (*PallasScalarField) Min(x algebra.ChainElement[curves.ScalarField, curves.Scalar], ys ...algebra.ChainElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	theMin := x
	for _, y := range ys {
		theMin = theMin.Min(y.Unwrap())
	}
	return theMin.Unwrap()
}
