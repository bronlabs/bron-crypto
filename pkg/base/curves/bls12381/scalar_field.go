package bls12381

import (
	"io"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	bls12381impl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

var (
	bls12381G1ScalarFieldInitOnce sync.Once
	bls12381G1ScalarFieldInstance ScalarField[G1]

	bls12381G2ScalarFieldInitOnce sync.Once
	bls12381G2ScalarFieldInstance ScalarField[G2]
)

var _ curves.ScalarField = (*ScalarField[G1])(nil)
var _ curves.ScalarField = (*ScalarField[G2])(nil)

type ScalarField[S SourceSubGroups] struct {
	_ ds.Incomparable
}

func bls12381G1ScalarFieldInit() {
	bls12381G1ScalarFieldInstance = ScalarField[G1]{}
}

func bls12381G2ScalarFieldInit() {
	bls12381G2ScalarFieldInstance = ScalarField[G2]{}
}

func NewScalarFieldG1() *ScalarField[G1] {
	bls12381G1ScalarFieldInitOnce.Do(bls12381G1ScalarFieldInit)
	return &bls12381G1ScalarFieldInstance
}

func NewScalarFieldG2() *ScalarField[G2] {
	bls12381G2ScalarFieldInitOnce.Do(bls12381G2ScalarFieldInit)
	return &bls12381G2ScalarFieldInstance
}

func (*ScalarField[S]) Curve() curves.Curve {
	return GetSourceSubGroup[S]()
}

func (*ScalarField[_]) Cardinality() *saferith.Modulus {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) Contains(e curves.Scalar) bool {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) Iter() <-chan curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (sf *ScalarField[_]) Unwrap() curves.ScalarField {
	return sf
}

func (*ScalarField[_]) IsDefinedUnder(operator algebra.BinaryOperator[curves.Scalar]) bool {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) Op(operator algebra.BinaryOperator[curves.Scalar], x algebra.GroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.GroupoidElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) Addition() algebra.Addition[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) Exp(b curves.Scalar, power curves.Scalar) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) Operators() []algebra.BinaryOperator[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) SimExp(bases []algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], exponents []*saferith.Nat) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) MultiBaseExp(bases []algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], exponent *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) MultiExponentExp(b algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], exponents []*saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) Multiplication() algebra.Multiplication[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) DiscreteExponentiation() algebra.DiscreteExponentiation[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) Identity(under algebra.BinaryOperator[curves.Scalar]) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) CoPrime(x curves.Scalar, ys ...curves.Scalar) bool {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) GCD(x curves.Scalar, ys ...curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) LCM(x curves.Scalar, ys ...curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) MultiplicativeGroup() algebra.MultiplicativeGroup[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) VectorSpace() algebra.VectorSpace[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) LatticeElement() algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) ChainElement() algebra.ChainElement[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) And(x algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) ConjunctiveIdentity() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) Or(x algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) DisjunctiveIdentity() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) ExclusiveDisjunctiveIdentity() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) ElementSize() int {
	return base.FieldBytes
}

func (*ScalarField[_]) WideElementSize() int {
	return base.WideFieldBytes
}

func (*ScalarField[_]) IsDecomposable(coprimeIdealNorms ...algebra.IntegerRingElement[curves.ScalarField, curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[_]) Scalar() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ScalarField[G]) Name() string {
	return GetSourceSubGroup[G]().Name()
}

func (*ScalarField[_]) Order() *saferith.Modulus {
	return r
}

func (sf *ScalarField[_]) Element() curves.Scalar {
	return sf.AdditiveIdentity()
}

func (sf *ScalarField[_]) Random(prng io.Reader) (curves.Scalar, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	var buffer [base.WideFieldBytes]byte
	_, err := io.ReadFull(prng, buffer[:])
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not read from prng")
	}
	res, _ := sf.Element().SetBytesWide(buffer[:])
	return res, nil
}

func (sf *ScalarField[_]) Hash(x []byte) (curves.Scalar, error) {
	u, err := sf.Curve().HashToScalars(1, x, nil)
	if err != nil {
		return nil, errs.WrapHashing(err, "hash to scalar for bls12381 failed")
	}
	return u[0], nil
}

func (sf *ScalarField[_]) Select(choice bool, x0, x1 curves.Scalar) curves.Scalar {
	x0s, ok0 := x0.(*Scalar)
	x1s, ok1 := x1.(*Scalar)
	s, oks := sf.Element().(*Scalar)
	if !ok0 || !ok1 || oks {
		panic("Not a BLS12381 scalar")
	}
	s.V.CMove(x0s.V, x1s.V, utils.BoolTo[int](choice))
	return s
}

// === Additive Groupoid Methods.

func (*ScalarField[_]) Add(x algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Multiplicative Groupoid Methods.

func (*ScalarField[_]) Mul(x algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	result := x
	for _, y := range ys {
		result = result.Mul(y)
	}
	return result.Unwrap()
}

// === Additive Monoid Methods.

func (*ScalarField[S]) AdditiveIdentity() curves.Scalar {
	return &Scalar{
		V: bls12381impl.FqNew().SetZero(),
		G: GetSourceSubGroup[S](),
	}
}

// === Multiplicative Monoid Methods.

func (*ScalarField[S]) MultiplicativeIdentity() curves.Scalar {
	return &Scalar{
		V: bls12381impl.FqNew().SetOne(),
		G: GetSourceSubGroup[S](),
	}
}

// === Additive Group Methods.

func (*ScalarField[_]) Sub(x algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar], ys ...algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	result := x
	for _, y := range ys {
		result = result.Sub(y)
	}
	return result.Unwrap()
}

// === Multiplicative Group Methods.

func (*ScalarField[_]) Div(x algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar], ys ...algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
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

func (*ScalarField[S]) QuadraticResidue(s algebra.RingElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	ss, ok := s.(*Scalar)
	if !ok {
		return nil, errs.NewType("given point is not from this field")
	}
	ss.G = GetSourceSubGroup[S]()
	return ss.Sqrt()
}

// === Finite Field Methods.

func (sf *ScalarField[_]) Characteristic() *saferith.Nat {
	return sf.Order().Nat()
}

func (*ScalarField[_]) ExtensionDegree() *saferith.Nat {
	return saferithUtils.NatOne
}

func (sf *ScalarField[S]) FrobeniusAutomorphism(e curves.Scalar) curves.Scalar {
	return e.Exp(sf.Characteristic())
}

func (sf *ScalarField[_]) Trace(e curves.Scalar) curves.Scalar {
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

func (*ScalarField[_]) FieldBytes() int {
	return base.FieldBytes
}

func (*ScalarField[_]) WideFieldBytes() int {
	return base.WideFieldBytes
}

// === Zp Methods.

func (*ScalarField[S]) New(value uint64) curves.Scalar {
	return GetSourceSubGroup[S]().ScalarField().Element().SetNat(new(saferith.Nat).SetUint64(value))
}

func (sf *ScalarField[_]) Zero() curves.Scalar {
	return sf.AdditiveIdentity()
}

func (sf *ScalarField[_]) One() curves.Scalar {
	return sf.MultiplicativeIdentity()
}

// === Ordering Methods.

func (sf *ScalarField[_]) Top() curves.Scalar {
	return sf.Zero().Sub(sf.One())
}

func (sf *ScalarField[_]) Bottom() curves.Scalar {
	return sf.Zero()
}

func (*ScalarField[_]) Join(x algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar], y algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return x.Join(y)
}

func (*ScalarField[_]) Meet(x algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar], y algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return x.Meet(y)
}

func (*ScalarField[_]) Max(x algebra.ChainElement[curves.ScalarField, curves.Scalar], ys ...algebra.ChainElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	theMax := x
	for _, y := range ys {
		theMax = theMax.Max(y.Unwrap())
	}
	return theMax.Unwrap()
}

func (*ScalarField[_]) Min(x algebra.ChainElement[curves.ScalarField, curves.Scalar], ys ...algebra.ChainElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	theMin := x
	for _, y := range ys {
		theMin = theMin.Min(y.Unwrap())
	}
	return theMin.Unwrap()
}
