package kuiper

import (
	"encoding"
	"encoding/json"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/arithmetic/limb7"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/kuiper/impl/fp"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var _ curves.Scalar = (*ErisScalar)(nil)
var _ encoding.BinaryMarshaler = (*ErisScalar)(nil)
var _ encoding.BinaryUnmarshaler = (*ErisScalar)(nil)
var _ json.Unmarshaler = (*ErisScalar)(nil)

type ErisScalar struct {
	V *limb7.FieldValue

	_ ds.Incomparable
}

func NewErisScalar(value uint64) *ErisScalar {
	return &ErisScalar{
		V: fp.NewFp().SetUint64(value),
	}
}

// === Basic Methods.

func (*ErisScalar) Structure() curves.ScalarField {
	return NewErisScalarField()
}

func (s *ErisScalar) Unwrap() curves.Scalar {
	return s
}

func (*ErisScalar) Order(operator algebra.BinaryOperator[curves.Scalar]) (*saferith.Modulus, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) ApplyOp(operator algebra.BinaryOperator[curves.Scalar], x algebra.GroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) IsIdentity(under algebra.BinaryOperator[curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) Inverse(under algebra.BinaryOperator[curves.Scalar]) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) IsInverse(of algebra.GroupElement[curves.ScalarField, curves.Scalar], under algebra.BinaryOperator[curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) CoPrime(x curves.Scalar) bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) GCD(x curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) LCM(x curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) Factorise() []curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) EuclideanDiv(x curves.Scalar) (quotient curves.Scalar, reminder curves.Scalar) {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) IsTorsionElementUnderMultiplication(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) Lattice() algebra.OrderTheoreticLattice[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) Next() (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) Previous() (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) Chain() algebra.Chain[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) IsNonZero() bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) IsPositive() bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) Int() algebra.Int {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) FromInt(v algebra.Int) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) Not() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) And(x algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) ApplyAnd(x algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) IsConjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) Or(x algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) ApplyOr(x algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) IsDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) ApplyXor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) IsExclusiveDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) ExclusiveDisjunctiveInverse() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) IsExclusiveDisjunctiveInverse(of algebra.ExclusiveDisjunctiveGroupElement[curves.ScalarField, curves.Scalar]) bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) Lsh(bits uint) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) Rsh(bits uint) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) BytesLE() []byte {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) SetBytesLE(bytes []byte) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisScalar) SetBytesWideLE(bytes []byte) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (s *ErisScalar) Equal(rhs curves.Scalar) bool {
	return s.Cmp(rhs) == 0
}

func (s *ErisScalar) Clone() curves.Scalar {
	return &ErisScalar{
		V: fp.NewFp().Set(s.V),
	}
}

// === Additive Groupoid Methods.

func (s *ErisScalar) Add(rhs algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*ErisScalar)
	if ok {
		return &ErisScalar{
			V: fp.NewFp().Add(s.V, r.V),
		}
	} else {
		panic("rhs is not Eris scalar")
	}
}

func (s *ErisScalar) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(ErisScalar).SetNat(n)
	return s.Add(x.Unwrap().Mul(reducedN))
}

func (s *ErisScalar) Double() curves.Scalar {
	return &ErisScalar{
		V: fp.NewFp().Double(s.V),
	}
}

func (s *ErisScalar) Triple() curves.Scalar {
	return s.Double().Add(s)
}

// === Multiplicative Groupoid Methods.

func (s *ErisScalar) Mul(rhs algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*ErisScalar)
	if ok {
		return &ErisScalar{
			V: fp.NewFp().Mul(s.V, r.V),
		}
	} else {
		panic("rhs is not Eris scalar")
	}
}

func (s *ErisScalar) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	return s.Mul(x.Unwrap().Exp(n))
}

func (s *ErisScalar) Square() curves.Scalar {
	return &ErisScalar{
		V: fp.NewFp().Square(s.V),
	}
}

func (s *ErisScalar) Cube() curves.Scalar {
	value := fp.NewFp().Mul(s.V, s.V)
	value.Mul(value, s.V)
	return &ErisScalar{
		V: value,
	}
}

// === Additive Monoid Methods.

func (s *ErisScalar) IsAdditiveIdentity() bool {
	return s.V.IsZero() == 1
}

// === Multiplicative Monoid Methods.

func (s *ErisScalar) IsMultiplicativeIdentity() bool {
	return s.V.IsOne() == 1
}

// === Additive Group Methods.

func (s *ErisScalar) AdditiveInverse() curves.Scalar {
	return &ErisScalar{
		V: fp.NewFp().Neg(s.V),
	}
}

func (s *ErisScalar) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Add(of).IsAdditiveIdentity()
}

func (s *ErisScalar) Sub(rhs algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*ErisScalar)
	if ok {
		return &ErisScalar{
			V: fp.NewFp().Sub(s.V, r.V),
		}
	} else {
		panic("rhs is not Eris scalar")
	}
}

func (s *ErisScalar) ApplySub(x algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(ErisScalar).SetNat(n)
	return s.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (s *ErisScalar) MultiplicativeInverse() (curves.Scalar, error) {
	value, wasInverted := fp.NewFp().Invert(s.V)
	if !wasInverted {
		return nil, errs.NewFailed("inverse doesn't exist")
	}

	return &ErisScalar{
		V: value,
	}, nil
}

func (s *ErisScalar) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Mul(of).IsMultiplicativeIdentity()
}

func (s *ErisScalar) Div(rhs algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	r, ok := rhs.(*ErisScalar)
	if ok {
		v, wasInverted := fp.NewFp().Invert(r.V)
		if !wasInverted {
			return nil, errs.NewFailed("cannot invert rhs")
		}
		v.Mul(v, s.V)
		return &ErisScalar{V: v}, nil
	} else {
		return nil, errs.NewFailed("rhs is not Eris scalar")
	}
}

func (s *ErisScalar) ApplyDiv(x algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) (curves.Scalar, error) {
	return s.Div(x.Exp(n))
}

// === Ring Methods.

func (s *ErisScalar) Sqrt() (curves.Scalar, error) {
	value, wasSquare := fp.NewFp().Sqrt(s.V)
	if !wasSquare {
		return nil, errs.NewFailed("not a square")
	}
	return &ErisScalar{
		V: value,
	}, nil
}

func (s *ErisScalar) MulAdd(p algebra.RingElement[curves.ScalarField, curves.Scalar], q algebra.RingElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return s.Mul(p).Add(q)
}

// === Finite Field Methods.

func (s *ErisScalar) SubFieldElement(index uint) curves.Scalar {
	return s
}

func (s *ErisScalar) Norm() curves.Scalar {
	return s
}

// === Zp Methods.

func (s *ErisScalar) Exp(e *saferith.Nat) curves.Scalar {
	exponent, ok := s.Structure().Element().SetNat(e).(*ErisScalar)
	if !ok {
		panic("rhs is not Eris scalar")
	}

	value := fp.NewFp().Exp(s.V, exponent.V)
	return &ErisScalar{V: value}
}

func (s *ErisScalar) Neg() curves.Scalar {
	return s.AdditiveInverse()
}

func (s *ErisScalar) IsZero() bool {
	return s.V.IsZero() == 1
}

func (s *ErisScalar) IsOne() bool {
	return s.V.IsOne() == 1
}

func (s *ErisScalar) IsOdd() bool {
	return s.V.Bytes()[0]&1 == 1
}

func (s *ErisScalar) IsEven() bool {
	return s.V.Bytes()[0]&1 == 0
}

func (s *ErisScalar) Increment() curves.Scalar {
	ee, ok := s.Add(s.ScalarField().One()).(*ErisScalar)
	if !ok {
		panic("invalid type")
	}
	return ee
}

func (s *ErisScalar) Decrement() curves.Scalar {
	ee, ok := s.Sub(s.ScalarField().One()).(*ErisScalar)
	if !ok {
		panic("invalid type")
	}
	return ee
}

// === Ordering Methods.

func (s *ErisScalar) Cmp(rhs algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) algebra.Ordering {
	r, ok := rhs.(*ErisScalar)
	if ok {
		return algebra.Ordering(s.V.Cmp(r.V))
	} else {
		panic("rhs is not Eris scalar")
	}
}

func (s *ErisScalar) IsBottom() bool {
	return s.IsZero()
}

func (s *ErisScalar) IsTop() bool {
	return s.Add(s.ScalarField().One()).IsZero()
}

func (s *ErisScalar) Join(rhs algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return s.Max(rhs.Unwrap())
}

func (s *ErisScalar) Max(rhs curves.Scalar) curves.Scalar {
	switch s.Cmp(rhs) {
	case algebra.Incomparable:
		panic("incomparable")
	case algebra.LessThan:
		return rhs
	case algebra.Equal, algebra.GreaterThan:
		return s
	default:
		panic("comparison output not supported")
	}
}

func (s *ErisScalar) Meet(rhs algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return s.Min(rhs.Unwrap())
}

func (s *ErisScalar) Min(rhs curves.Scalar) curves.Scalar {
	switch s.Cmp(rhs) {
	case algebra.Incomparable:
		panic("incomparable")
	case algebra.LessThan, algebra.Equal:
		return s
	case algebra.GreaterThan:
		return rhs
	default:
		panic("comparison output not supported")
	}
}

// === Curve Methods.

func (*ErisScalar) ScalarField() curves.ScalarField {
	return NewErisScalarField()
}

// === Serialisation.

func (s *ErisScalar) Uint64() uint64 {
	return s.Nat().Big().Uint64()
}

func (*ErisScalar) SetNat(v *saferith.Nat) curves.Scalar {
	if v == nil {
		return nil
	}
	value := fp.NewFp().SetNat(v)
	return &ErisScalar{
		V: value,
	}
}

func (s *ErisScalar) Nat() *saferith.Nat {
	return s.V.Nat()
}

func (s *ErisScalar) Bytes() []byte {
	t := s.V.Bytes()
	return bitstring.ReverseBytes(t[:])
}

func (*ErisScalar) SetBytes(input []byte) (curves.Scalar, error) {
	if len(input) != limb7.FieldBytes {
		return nil, errs.NewLength("invalid length")
	}
	input = bitstring.ReverseBytes(input)
	value, err := fp.NewFp().SetBytes((*[limb7.FieldBytes]byte)(input))
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set bytes")
	}
	return &ErisScalar{
		V: value,
	}, nil
}

func (*ErisScalar) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) > limb7.WideFieldBytes {
		return nil, errs.NewLength("invalid length (%d > %d bytes)", len(input), limb7.WideFieldBytes)
	}
	input = bitstring.PadToRight(bitstring.ReverseBytes(input), limb7.WideFieldBytes-len(input))
	return &ErisScalar{
		V: fp.NewFp().SetBytesWide((*[limb7.WideFieldBytes]byte)(input)),
	}, nil
}

func (s *ErisScalar) MarshalBinary() ([]byte, error) {
	res := impl.MarshalBinary(s.ScalarField().Curve().Name(), s.Bytes)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (s *ErisScalar) UnmarshalBinary(input []byte) error {
	sc, err := impl.UnmarshalBinary(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
	}
	name, _, err := impl.ParseBinary(input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract name from input")
	}
	if name != s.ScalarField().Name() {
		return errs.NewType("name %s is not supported", name)
	}
	ss, ok := sc.(*ErisScalar)
	if !ok {
		return errs.NewType("invalid base field element")
	}
	s.V = ss.V
	return nil
}

func (s *ErisScalar) MarshalJSON() ([]byte, error) {
	res, err := impl.MarshalJson(s.ScalarField().Curve().Name(), s.Bytes)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (s *ErisScalar) UnmarshalJSON(input []byte) error {
	sc, err := impl.UnmarshalJson(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract a base field element from json")
	}
	name, _, err := impl.ParseJSON(input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract name from input")
	}
	if name != s.ScalarField().Name() {
		return errs.NewType("name %s is not supported", name)
	}
	S, ok := sc.(*ErisScalar)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.V = S.V
	return nil
}

func (s *ErisScalar) HashCode() uint64 {
	return s.Uint64()
}
