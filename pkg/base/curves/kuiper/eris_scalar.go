package kuiper

import (
	"encoding"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	impl2 "github.com/copperexchange/krypton-primitives/pkg/base/curves/kuiper/impl"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

var (
	_ curves.Scalar              = (*ErisScalar)(nil)
	_ encoding.BinaryMarshaler   = (*ErisScalar)(nil)
	_ encoding.BinaryUnmarshaler = (*ErisScalar)(nil)
	_ json.Unmarshaler           = (*ErisScalar)(nil)
)

type ErisScalar struct {
	V impl2.Fp

	_ ds.Incomparable
}

func NewErisScalar(value uint64) (*ErisScalar, error) {
	z := &ErisScalar{}
	z.V.SetUint64(value)
	return z, nil
}

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
	rhse := rhs.(*ErisScalar)
	return s.V.Equal(&rhse.V) == 1
}

func (s *ErisScalar) Clone() curves.Scalar {
	z := &ErisScalar{}
	z.V.Set(&s.V)
	return z
}

// === Additive Groupoid Methods.

func (s *ErisScalar) Add(rhs algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*ErisScalar)
	if ok {
		z := &ErisScalar{}
		z.V.Add(&s.V, &r.V)
		return z
	} else {
		panic("rhs is not Eris")
	}
}

func (s *ErisScalar) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(ErisScalar).SetNat(n).(*ErisScalar)
	return s.Add(x.Unwrap().Mul(reducedN))
}

func (s *ErisScalar) Double() curves.Scalar {
	z := &ErisScalar{}
	z.V.Double(&s.V)
	return z
}

func (s *ErisScalar) Triple() curves.Scalar {
	return s.Double().Add(s)
}

// === Multiplicative Groupoid Methods.

func (s *ErisScalar) Mul(rhs algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*ErisScalar)
	if ok {
		z := &ErisScalar{}
		z.V.Mul(&s.V, &r.V)
		return z
	} else {
		panic("rhs is not Eris scalar")
	}
}

func (s *ErisScalar) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	return s.Mul(x.Exp(n))
}

func (s *ErisScalar) Square() curves.Scalar {
	z := &ErisScalar{}
	z.V.Square(&s.V)
	return z
}

func (s *ErisScalar) Cube() curves.Scalar {
	return s.Square().Mul(s)
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
	z := &ErisScalar{}
	z.V.Neg(&s.V)
	return z
}

func (s *ErisScalar) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Add(of).IsAdditiveIdentity()
}

func (s *ErisScalar) Sub(rhs algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*ErisScalar)
	if ok {
		z := &ErisScalar{}
		z.V.Sub(&s.V, &r.V)
		return z
	} else {
		panic("rhs is not Eris")
	}
}

func (s *ErisScalar) ApplySub(x algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(ErisScalar).SetNat(n).(*ErisScalar)
	return s.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (s *ErisScalar) MultiplicativeInverse() (curves.Scalar, error) {
	value, wasInverted := new(impl2.Fp).Invert(&s.V)
	if wasInverted != 1 {
		return nil, errs.NewFailed("inverse doesn't exist")
	}

	z := &ErisScalar{}
	s.V = *value
	return z, nil
}

func (s *ErisScalar) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Mul(of).IsMultiplicativeIdentity()
}

func (s *ErisScalar) Div(rhs algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	r, ok := rhs.(*ErisScalar)
	if ok {
		v, wasInverted := new(impl2.Fp).Invert(&r.V)
		if wasInverted != 1 {
			return nil, errs.NewFailed("cannot invert scalar")
		}
		z := &ErisScalar{}
		z.V.Mul(&s.V, v)
		return z, nil
	} else {
		return nil, errs.NewFailed("rhs is not Eris")
	}
}

func (s *ErisScalar) ApplyDiv(x algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) (curves.Scalar, error) {
	return s.Div(x.Exp(n))
}

// === Ring Methods.

func (s *ErisScalar) Sqrt() (curves.Scalar, error) {
	value, wasSquare := new(impl2.Fp).Sqrt(&s.V)
	if wasSquare != 1 {
		return nil, errs.NewFailed("not a square")
	}
	z := &ErisScalar{}
	z.V = *value
	return z, nil
}

func (s *ErisScalar) MulAdd(y algebra.RingElement[curves.ScalarField, curves.Scalar], z algebra.RingElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return s.Mul(y).Add(z)
}

// === Finite Field Methods.

func (s *ErisScalar) SubFieldElement(index uint) curves.Scalar {
	return s
}

func (s *ErisScalar) Norm() curves.Scalar {
	return s
}

// === Zp Methods.

func (s *ErisScalar) Exp(k *saferith.Nat) curves.Scalar {
	exp, ok := s.Structure().Element().SetNat(k).(*ErisScalar)
	if !ok {
		panic("rhs is not Eris")
	}

	value := new(impl2.Fp).Exp(&s.V, &exp.V)
	return &ErisScalar{
		V: *value,
	}
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
	bytes_ := s.V.Bytes()
	return bytes_[0]&1 == 1
}

func (s *ErisScalar) IsEven() bool {
	bytes_ := s.V.Bytes()
	return bytes_[0]&1 == 0
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
		return algebra.Ordering(s.V.Cmp(&r.V))
	} else {
		return algebra.Incomparable
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
	return &ErisScalar{
		V: *new(impl2.Fp).SetNat(v),
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
	if len(input) != base.FieldBytes {
		return nil, errs.NewLength("invalid length")
	}
	reducedInput := saferithUtils.NatFromBytesMod(input, impl2.FpModulus)
	buffer := bitstring.PadToRight(bitstring.ReverseBytes(reducedInput.Bytes()), impl2.FieldBytes-len(reducedInput.Bytes()))
	value, err := new(impl2.Fp).SetBytes((*[impl2.FieldBytes]byte)(buffer))
	if err != 1 {
		return nil, errs.NewSerialisation("couldn't set bytes")
	}
	return &ErisScalar{
		V: *value,
	}, nil
}

func (*ErisScalar) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) > impl2.WideFieldBytes {
		return nil, errs.NewLength("invalid length > %d", impl2.WideFieldBytes)
	}
	buffer := bitstring.PadToRight(bitstring.ReverseBytes(input), impl2.WideFieldBytes-len(input))
	value := new(impl2.Fp).SetBytesWide((*[impl2.WideFieldBytes]byte)(buffer))
	return &ErisScalar{
		V: *value,
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
	ss, ok := sc.(*ErisScalar)
	if !ok {
		return errs.NewType("invalid base field element")
	}
	s.V = ss.V
	_, _, err = impl.ParseBinary(input)
	if err != nil {
		return errs.WrapSerialisation(err, "couldn't extract name from input")
	}

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
	_, _, err := impl.ParseJSON(input)
	if err != nil {
		return errs.WrapSerialisation(err, "couldn't extract name from input")
	}

	sc, err := impl.UnmarshalJson(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract a base field element from json")
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
