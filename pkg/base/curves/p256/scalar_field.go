package p256

import (
	"io"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256/impl/fq"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

var (
	p256ScalarFieldInitOnce sync.Once
	p256ScalarFieldInstance ScalarField
)

var _ curves.ScalarField = (*ScalarField)(nil)

type ScalarField struct {
	algebra.BoundedOrderTheoreticLattice[curves.ScalarField, curves.Scalar]
	_ ds.Incomparable
}

func (*ScalarField) Arithmetic() integer.Arithmetic[curves.Scalar] {
	panic("not implemented")
}
func (*ScalarField) Factorise() []curves.Scalar {
	panic("not implemented")
}
func (*ScalarField) Module() algebra.Module[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	panic("not implemented")
}
func (*ScalarField) RandomPrime(prng io.Reader) curves.Scalar {
	panic("not implemented")
}

func p256ScalarFieldInit() {
	p256ScalarFieldInstance = ScalarField{}
}

func NewScalarField() *ScalarField {
	p256ScalarFieldInitOnce.Do(p256ScalarFieldInit)
	return &p256ScalarFieldInstance
}

func (*ScalarField) GetOperator(op algebra.Operator) (algebra.BinaryOperator[curves.Scalar], bool) {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) Cardinality() *saferith.Modulus {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) Contains(e curves.Scalar) bool {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) Iter() <-chan curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) Curve() curves.Curve {
	return NewCurve()
}

func (sf *ScalarField) Unwrap() curves.ScalarField {
	return sf
}

func (*ScalarField) IsDefinedUnder(operator algebra.Operator) bool {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) Operate(operator algebra.Operator, x algebra.GroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.GroupoidElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) Addition() algebra.Addition[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) Exp(b algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], exponent *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) Operators() []algebra.Operator {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) SimExp(bases []algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], exponents []*saferith.Nat) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) MultiBaseExp(bases []algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], exponent *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) MultiExponentExp(b algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], exponents []*saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) Multiplication() algebra.Multiplication[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) DiscreteExponentiation() algebra.DiscreteExponentiation[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) Identity(under algebra.Operator) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) CoPrime(x curves.Scalar, ys ...curves.Scalar) bool {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) GCD(x curves.Scalar, ys ...curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) LCM(x curves.Scalar, ys ...curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) MultiplicativeGroup() algebra.MultiplicativeGroup[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) VectorSpace() algebra.VectorSpace[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) LatticeElement() algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) ChainElement() algebra.ChainElement[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) And(x algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) ConjunctiveIdentity() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) Or(x algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) DisjunctiveIdentity() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) ExclusiveDisjunctiveIdentity() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) ElementSize() int {
	return base.FieldBytes
}

func (*ScalarField) WideElementSize() int {
	return base.WideFieldBytes
}

func (*ScalarField) IsDecomposable(coprimeIdealNorms ...integer.Uint[curves.ScalarField, curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) Scalar() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField) Name() string {
	return Name
}

func (*ScalarField) Order() *saferith.Modulus {
	return NewCurve().SubGroupOrder()
}

func (sf *ScalarField) Element() curves.Scalar {
	return sf.AdditiveIdentity()
}

func (*ScalarField) Random(prng io.Reader) (curves.Scalar, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	var seed [base.WideFieldBytes]byte
	_, err := io.ReadFull(prng, seed[:])
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not read from prng")
	}
	value, err := NewScalar(0).SetBytesWide(seed[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set bytes")
	}
	return value, nil
}

func (*ScalarField) Hash(x []byte) (curves.Scalar, error) {
	u, err := NewCurve().HashToScalars(1, x, nil)
	if err != nil {
		return nil, errs.WrapHashing(err, "hash to scalar failed for p256")
	}
	return u[0], nil
}

func (sf *ScalarField) Select(choice bool, x0, x1 curves.Scalar) curves.Scalar {
	x0s, ok0 := x0.(*Scalar)
	x1s, ok1 := x1.(*Scalar)
	s, oks := sf.Element().(*Scalar)
	if !ok0 || !ok1 || !oks {
		panic("Not a p256 scalar")
	}
	s.V.CMove(x0s.V, x1s.V, utils.BoolTo[int](choice))
	return s
}

// === Additive Groupoid Methods.

func (*ScalarField) Add(x algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Multiplicative Groupoid Methods.

func (*ScalarField) Mul(x algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	result := x
	for _, y := range ys {
		result = result.Mul(y)
	}
	return result.Unwrap()
}

// === Additive Monoid Methods.

func (*ScalarField) AdditiveIdentity() curves.Scalar {
	return &Scalar{
		V: fq.New().SetZero(),
	}
}

// === Multiplicative Monoid Methods.

func (*ScalarField) MultiplicativeIdentity() curves.Scalar {
	return &Scalar{
		V: fq.New().SetOne(),
	}
}

// === Additive Group Methods.

func (*ScalarField) Sub(x algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar], ys ...algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	result := x
	for _, y := range ys {
		result = result.Sub(y)
	}
	return result.Unwrap()
}

// === Multiplicative Group Methods.

func (*ScalarField) Div(x algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar], ys ...algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	result := x
	for _, y := range ys {
		var err error
		result, err = result.Div(y)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot divide")
		}
	}
	return result.Unwrap(), nil
}

// === Ring Methods.

func (*ScalarField) QuadraticResidue(s algebra.RingElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	ss, ok := s.(*Scalar)
	if !ok {
		return nil, errs.NewType("given point is not from this field")
	}
	return ss.Sqrt()
}

// === Finite Field Methods.

func (sf *ScalarField) Characteristic() *saferith.Nat {
	return sf.Order().Nat()
}

func (*ScalarField) ExtensionDegree() *saferith.Nat {
	return saferithUtils.NatOne
}

func (sf *ScalarField) FrobeniusAutomorphism(e curves.Scalar) curves.Scalar {
	return e.Exp(sf.Characteristic())
}

func (sf *ScalarField) Trace(e curves.Scalar) curves.Scalar {
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

func (*ScalarField) FieldBytes() int {
	return base.FieldBytes
}

func (*ScalarField) WideFieldBytes() int {
	return base.WideFieldBytes
}

// === Zp Methods.

func (*ScalarField) New(value uint64) curves.Scalar {
	return NewScalar(value)
}

func (sf *ScalarField) Zero() curves.Scalar {
	return sf.AdditiveIdentity()
}

func (sf *ScalarField) One() curves.Scalar {
	return sf.MultiplicativeIdentity()
}

// === Ordering Methods.

func (sf *ScalarField) Top() curves.Scalar {
	return sf.Zero().Sub(sf.One())
}

func (sf *ScalarField) Bottom() curves.Scalar {
	return sf.Zero()
}

func (*ScalarField) Join(x algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar], ys ...algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	panic("not implemented")
}

func (*ScalarField) Meet(x algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar], ys ...algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	panic("not implemented")
}

func (*ScalarField) Max(x algebra.ChainElement[curves.ScalarField, curves.Scalar], ys ...algebra.ChainElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	theMax := x
	for _, y := range ys {
		theMax = theMax.Max(y.Unwrap())
	}
	return theMax.Unwrap()
}

func (*ScalarField) Min(x algebra.ChainElement[curves.ScalarField, curves.Scalar], ys ...algebra.ChainElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	theMin := x
	for _, y := range ys {
		theMin = theMin.Min(y.Unwrap())
	}
	return theMin.Unwrap()
}
