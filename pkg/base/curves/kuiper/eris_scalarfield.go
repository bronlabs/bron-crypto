package kuiper

import (
	"io"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/kuiper/impl"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

var (
	erisScalarFieldInitOnce sync.Once
	erisScalarFieldInstance ErisScalarField
)

var _ curves.ScalarField = (*ErisScalarField)(nil)

type ErisScalarField struct {
	_ ds.Incomparable
}

func erisScalarFieldInit() {
	erisScalarFieldInstance = ErisScalarField{}
}

func NewErisScalarField() *ErisScalarField {
	erisScalarFieldInitOnce.Do(erisScalarFieldInit)
	return &erisScalarFieldInstance
}

func (*ErisScalarField) Curve() curves.Curve {
	return NewEris()
}

func (*ErisScalarField) Cardinality() *saferith.Nat {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) Contains(e curves.Scalar) bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) Iterator() ds.Iterator[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (sf *ErisScalarField) Unwrap() curves.ScalarField {
	return sf
}

func (*ErisScalarField) IsDefinedUnder(operator algebra.BinaryOperator[curves.Scalar]) bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) Op(operator algebra.BinaryOperator[curves.Scalar], x algebra.GroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.GroupoidElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) Addition() algebra.Addition[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) Exp(b curves.Scalar, power curves.Scalar) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) Operators() []algebra.BinaryOperator[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) SimExp(bases []algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], exponents []*saferith.Nat) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) MultiBaseExp(bases []algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], exponent *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) MultiExponentExp(b algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], exponents []*saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) Multiplication() algebra.Multiplication[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) DiscreteExponentiation() algebra.DiscreteExponentiation[curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) Identity(under algebra.BinaryOperator[curves.Scalar]) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) CoPrime(x curves.Scalar, ys ...curves.Scalar) bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) GCD(x curves.Scalar, ys ...curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) LCM(x curves.Scalar, ys ...curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) MultiplicativeGroup() algebra.MultiplicativeGroup[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) VectorSpace() algebra.VectorSpace[curves.Curve, curves.ScalarField, curves.Point, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) LatticeElement() algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) ChainElement() algebra.ChainElement[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) And(x algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) ConjunctiveIdentity() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) Or(x algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) DisjunctiveIdentity() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) ExclusiveDisjunctiveIdentity() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalarField) ElementSize() int {
	return base.FieldBytes
}

func (*ErisScalarField) WideElementSize() int {
	return base.WideFieldBytes
}

func (*ErisScalarField) IsDecomposable(coprimeIdealNorms ...algebra.IntegerRingElement[curves.ScalarField, curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (sf *ErisScalarField) Scalar() curves.Scalar {
	return sf.Element()
}

func (*ErisScalarField) Name() string {
	return NewEris().Name()
}

func (*ErisScalarField) Order() *saferith.Modulus {
	return impl.FpModulus
}

func (sf *ErisScalarField) Element() curves.Scalar {
	return sf.AdditiveIdentity()
}

func (sf *ErisScalarField) Random(prng io.Reader) (curves.Scalar, error) {
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

func (*ErisScalarField) Hash(x []byte) (curves.Scalar, error) {
	panic("not implemented")
}

func (sf *ErisScalarField) Select(choice bool, x0, x1 curves.Scalar) curves.Scalar {
	x0s, ok0 := x0.(*PlutoTritonScalar)
	x1s, ok1 := x1.(*PlutoTritonScalar)
	s, oks := sf.Element().(*PlutoTritonScalar)
	if !ok0 || !ok1 || oks {
		panic("Not a Pluto/Triton scalar")
	}
	s.V.CMove(&x0s.V, &x1s.V, utils.BoolTo[uint64](choice))
	return s
}

// === Additive Groupoid Methods.

func (*ErisScalarField) Add(x algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	sum := x
	for _, y := range ys {
		sum = sum.Add(y)
	}
	return sum.Unwrap()
}

// === Multiplicative Groupoid Methods.

func (*ErisScalarField) Mul(x algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	result := x
	for _, y := range ys {
		result = result.Mul(y)
	}
	return result.Unwrap()
}

// === Additive Monoid Methods.

func (*ErisScalarField) AdditiveIdentity() curves.Scalar {
	return &ErisScalar{
		V: *new(impl.Fp).SetZero(),
	}
}

// === Multiplicative Monoid Methods.

func (*ErisScalarField) MultiplicativeIdentity() curves.Scalar {
	return &ErisScalar{
		V: *new(impl.Fp).SetOne(),
	}
}

// === Additive Group Methods.

func (*ErisScalarField) Sub(x algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar], ys ...algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	result := x
	for _, y := range ys {
		result = result.Sub(y)
	}
	return result.Unwrap()
}

// === Multiplicative Group Methods.

func (*ErisScalarField) Div(x algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar], ys ...algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
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

func (*ErisScalarField) QuadraticResidue(s algebra.RingElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	ss, ok := s.(*PlutoTritonScalar)
	if !ok {
		return nil, errs.NewType("given point is not from this field")
	}

	return ss.Sqrt()
}

// === Finite Field Methods.

func (sf *ErisScalarField) Characteristic() *saferith.Nat {
	return sf.Order().Nat()
}

func (*ErisScalarField) ExtensionDegree() *saferith.Nat {
	return saferithUtils.NatOne
}

func (sf *ErisScalarField) FrobeniusAutomorphism(e curves.Scalar) curves.Scalar {
	return e.Exp(sf.Characteristic())
}

func (sf *ErisScalarField) Trace(e curves.Scalar) curves.Scalar {
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

func (*ErisScalarField) FieldBytes() int {
	return base.FieldBytes
}

func (*ErisScalarField) WideFieldBytes() int {
	return base.WideFieldBytes
}

// === Zp Methods.

func (*ErisScalarField) New(value uint64) curves.Scalar {
	return NewErisScalarField().Element().SetNat(new(saferith.Nat).SetUint64(value))
}

func (sf *ErisScalarField) Zero() curves.Scalar {
	return sf.AdditiveIdentity()
}

func (sf *ErisScalarField) One() curves.Scalar {
	return sf.MultiplicativeIdentity()
}

// === Ordering Methods.

func (sf *ErisScalarField) Top() curves.Scalar {
	return sf.Zero().Sub(sf.One())
}

func (sf *ErisScalarField) Bottom() curves.Scalar {
	return sf.Zero()
}

func (*ErisScalarField) Join(x algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar], y algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return x.Join(y)
}

func (*ErisScalarField) Meet(x algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar], y algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return x.Meet(y)
}

func (*ErisScalarField) Max(x algebra.ChainElement[curves.ScalarField, curves.Scalar], ys ...algebra.ChainElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	theMax := x
	for _, y := range ys {
		theMax = theMax.Max(y.Unwrap())
	}
	return theMax.Unwrap()
}

func (*ErisScalarField) Min(x algebra.ChainElement[curves.ScalarField, curves.Scalar], ys ...algebra.ChainElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	theMin := x
	for _, y := range ys {
		theMin = theMin.Min(y.Unwrap())
	}
	return theMin.Unwrap()
}
