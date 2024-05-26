package kuiper

import (
	"encoding"
	"encoding/json"
	"fmt"

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
	_ curves.Scalar              = (*PlutoTritonScalar)(nil)
	_ encoding.BinaryMarshaler   = (*PlutoTritonScalar)(nil)
	_ encoding.BinaryUnmarshaler = (*PlutoTritonScalar)(nil)
	_ json.Unmarshaler           = (*PlutoTritonScalar)(nil)
)

type PlutoTritonScalar struct {
	V impl2.Fq
	G curves.Curve

	_ ds.Incomparable
}

func NewPlutoTritonScalar(subgroup curves.Curve, value uint64) (*PlutoTritonScalar, error) {
	if subgroup.Name() != NewPluto().Name() && subgroup.Name() != NewTriton().Name() {
		return nil, errs.NewCurve("subgroup %s is not one of the bls source subgroups", subgroup.Name())
	}

	z := &PlutoTritonScalar{G: subgroup}
	z.V.SetUint64(value)
	return z, nil
}

func (s *PlutoTritonScalar) Structure() curves.ScalarField {
	if s.G.Name() == NewPluto().Name() {
		return NewPlutoScalarField()
	} else if s.G.Name() == NewTriton().Name() {
		return NewTritonScalarField()
	} else {
		panic("invalid scalar")
	}
}

func (s *PlutoTritonScalar) Unwrap() curves.Scalar {
	return s
}

func (*PlutoTritonScalar) Order(operator algebra.BinaryOperator[curves.Scalar]) (*saferith.Modulus, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) ApplyOp(operator algebra.BinaryOperator[curves.Scalar], x algebra.GroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) IsIdentity(under algebra.BinaryOperator[curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) Inverse(under algebra.BinaryOperator[curves.Scalar]) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) IsInverse(of algebra.GroupElement[curves.ScalarField, curves.Scalar], under algebra.BinaryOperator[curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) CoPrime(x curves.Scalar) bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) GCD(x curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) LCM(x curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) Factorise() []curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) EuclideanDiv(x curves.Scalar) (quotient curves.Scalar, reminder curves.Scalar) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) IsTorsionElementUnderMultiplication(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) Lattice() algebra.OrderTheoreticLattice[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) Next() (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) Previous() (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) Chain() algebra.Chain[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) IsNonZero() bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) IsPositive() bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) Int() algebra.Int {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) FromInt(v algebra.Int) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) Not() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) And(x algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) ApplyAnd(x algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) IsConjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) Or(x algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) ApplyOr(x algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) IsDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) ApplyXor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) IsExclusiveDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) ExclusiveDisjunctiveInverse() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) IsExclusiveDisjunctiveInverse(of algebra.ExclusiveDisjunctiveGroupElement[curves.ScalarField, curves.Scalar]) bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) Lsh(bits uint) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) Rsh(bits uint) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) BytesLE() []byte {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) SetBytesLE(bytes []byte) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoTritonScalar) SetBytesWideLE(bytes []byte) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (s *PlutoTritonScalar) Equal(rhs curves.Scalar) bool {
	rhse := rhs.(*PlutoTritonScalar)
	return s.V.Equal(&rhse.V) == 1
}

func (s *PlutoTritonScalar) Clone() curves.Scalar {
	z := &PlutoTritonScalar{G: s.G}
	z.V.Set(&s.V)
	return z
}

// === Additive Groupoid Methods.

func (s *PlutoTritonScalar) Add(rhs algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*PlutoTritonScalar)
	if ok {
		z := &PlutoTritonScalar{G: s.G}
		z.V.Add(&s.V, &r.V)
		return z
	} else {
		panic("rhs is not Pluto/Triton")
	}
}

func (s *PlutoTritonScalar) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(PlutoTritonScalar).SetNat(n).(*PlutoTritonScalar)
	reducedN.G = s.G
	return s.Add(x.Unwrap().Mul(reducedN))
}

func (s *PlutoTritonScalar) Double() curves.Scalar {
	z := &PlutoTritonScalar{G: s.G}
	z.V.Double(&s.V)
	return z
}

func (s *PlutoTritonScalar) Triple() curves.Scalar {
	return s.Double().Add(s)
}

// === Multiplicative Groupoid Methods.

func (s *PlutoTritonScalar) Mul(rhs algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*PlutoTritonScalar)
	if ok {
		z := &PlutoTritonScalar{G: s.G}
		z.V.Mul(&s.V, &r.V)
		return z
	} else {
		panic("rhs is not Pluto/Triton scalar")
	}
}

func (s *PlutoTritonScalar) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	return s.Mul(x.Exp(n))
}

func (s *PlutoTritonScalar) Square() curves.Scalar {
	z := &PlutoTritonScalar{G: s.G}
	z.V.Square(&s.V)
	return z
}

func (s *PlutoTritonScalar) Cube() curves.Scalar {
	return s.Square().Mul(s)
}

// === Additive Monoid Methods.

func (s *PlutoTritonScalar) IsAdditiveIdentity() bool {
	return s.V.IsZero() == 1
}

// === Multiplicative Monoid Methods.

func (s *PlutoTritonScalar) IsMultiplicativeIdentity() bool {
	return s.V.IsOne() == 1
}

// === Additive Group Methods.

func (s *PlutoTritonScalar) AdditiveInverse() curves.Scalar {
	z := &PlutoTritonScalar{G: s.G}
	z.V.Neg(&s.V)
	return z
}

func (s *PlutoTritonScalar) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Add(of).IsAdditiveIdentity()
}

func (s *PlutoTritonScalar) Sub(rhs algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*PlutoTritonScalar)
	if ok {
		z := &PlutoTritonScalar{G: s.G}
		z.V.Sub(&s.V, &r.V)
		return z
	} else {
		panic("rhs is not Pluto/Triton")
	}
}

func (s *PlutoTritonScalar) ApplySub(x algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(PlutoTritonScalar).SetNat(n).(*PlutoTritonScalar)
	reducedN.G = s.G
	return s.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (s *PlutoTritonScalar) MultiplicativeInverse() (curves.Scalar, error) {
	value, wasInverted := new(impl2.Fq).Invert(&s.V)
	if wasInverted != 1 {
		return nil, errs.NewFailed("inverse doesn't exist")
	}

	z := &PlutoTritonScalar{G: s.G}
	s.V = *value
	return z, nil
}

func (s *PlutoTritonScalar) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Mul(of).IsMultiplicativeIdentity()
}

func (s *PlutoTritonScalar) Div(rhs algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	r, ok := rhs.(*PlutoTritonScalar)
	if ok {
		v, wasInverted := new(impl2.Fq).Invert(&r.V)
		if wasInverted != 1 {
			return nil, errs.NewFailed("cannot invert scalar")
		}
		z := &PlutoTritonScalar{G: s.G}
		z.V.Mul(&s.V, v)
		return z, nil
	} else {
		return nil, errs.NewFailed("rhs is not Pluto/Triton")
	}
}

func (s *PlutoTritonScalar) ApplyDiv(x algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) (curves.Scalar, error) {
	return s.Div(x.Exp(n))
}

// === Ring Methods.

func (s *PlutoTritonScalar) Sqrt() (curves.Scalar, error) {
	value, wasSquare := new(impl2.Fq).Sqrt(&s.V)
	if wasSquare != 1 {
		return nil, errs.NewFailed("not a square")
	}
	z := &PlutoTritonScalar{G: s.G}
	z.V = *value
	return z, nil
}

func (s *PlutoTritonScalar) MulAdd(y algebra.RingElement[curves.ScalarField, curves.Scalar], z algebra.RingElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return s.Mul(y).Add(z)
}

// === Finite Field Methods.

func (s *PlutoTritonScalar) SubFieldElement(index uint) curves.Scalar {
	return s
}

func (s *PlutoTritonScalar) Norm() curves.Scalar {
	return s
}

// === Zp Methods.

func (s *PlutoTritonScalar) Exp(k *saferith.Nat) curves.Scalar {
	exp, ok := s.Structure().Element().SetNat(k).(*PlutoTritonScalar)
	if !ok {
		panic("rhs is not Pluto/Triton")
	}

	value := new(impl2.Fq).Exp(&s.V, &exp.V)
	return &PlutoTritonScalar{
		V: *value,
		G: s.G,
	}
}

func (s *PlutoTritonScalar) Neg() curves.Scalar {
	return s.AdditiveInverse()
}

func (s *PlutoTritonScalar) IsZero() bool {
	return s.V.IsZero() == 1
}

func (s *PlutoTritonScalar) IsOne() bool {
	return s.V.IsOne() == 1
}

func (s *PlutoTritonScalar) IsOdd() bool {
	bytes_ := s.V.Bytes()
	return bytes_[0]&1 == 1
}

func (s *PlutoTritonScalar) IsEven() bool {
	bytes_ := s.V.Bytes()
	return bytes_[0]&1 == 0
}

func (s *PlutoTritonScalar) Increment() curves.Scalar {
	ee, ok := s.Add(s.ScalarField().One()).(*PlutoTritonScalar)
	if !ok {
		panic("invalid type")
	}
	return ee
}

func (s *PlutoTritonScalar) Decrement() curves.Scalar {
	ee, ok := s.Sub(s.ScalarField().One()).(*PlutoTritonScalar)
	if !ok {
		panic("invalid type")
	}
	return ee
}

// === Ordering Methods.

func (s *PlutoTritonScalar) Cmp(rhs algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) algebra.Ordering {
	r, ok := rhs.(*PlutoTritonScalar)
	if ok {
		return algebra.Ordering(s.V.Cmp(&r.V))
	} else {
		return algebra.Incomparable
	}
}

func (s *PlutoTritonScalar) IsBottom() bool {
	return s.IsZero()
}

func (s *PlutoTritonScalar) IsTop() bool {
	return s.Add(s.ScalarField().One()).IsZero()
}

func (s *PlutoTritonScalar) Join(rhs algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return s.Max(rhs.Unwrap())
}

func (s *PlutoTritonScalar) Max(rhs curves.Scalar) curves.Scalar {
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

func (s *PlutoTritonScalar) Meet(rhs algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return s.Min(rhs.Unwrap())
}

func (s *PlutoTritonScalar) Min(rhs curves.Scalar) curves.Scalar {
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

func (s *PlutoTritonScalar) ScalarField() curves.ScalarField {
	switch s.G.Name() {
	case NewPluto().Name():
		return NewPlutoScalarField()
	case NewTriton().Name():
		return NewTritonScalarField()
	default:
		panic(fmt.Sprintf("subgroup %s is not a bls source subgroup", s.G.Name()))
	}
}

// === Serialisation.

func (s *PlutoTritonScalar) Uint64() uint64 {
	return s.Nat().Big().Uint64()
}

func (s *PlutoTritonScalar) SetNat(v *saferith.Nat) curves.Scalar {
	if v == nil {
		return nil
	}
	return &PlutoTritonScalar{
		V: *new(impl2.Fq).SetNat(v),
		G: s.G,
	}
}

func (s *PlutoTritonScalar) Nat() *saferith.Nat {
	return s.V.Nat()
}

func (s *PlutoTritonScalar) Bytes() []byte {
	t := s.V.Bytes()
	return bitstring.ReverseBytes(t[:])
}

func (s *PlutoTritonScalar) SetBytes(input []byte) (curves.Scalar, error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewLength("invalid length")
	}
	reducedInput := saferithUtils.NatFromBytesMod(input, impl2.FqModulus)
	buffer := bitstring.PadToRight(bitstring.ReverseBytes(reducedInput.Bytes()), impl2.FieldBytes-len(reducedInput.Bytes()))
	value, err := new(impl2.Fq).SetBytes((*[impl2.FieldBytes]byte)(buffer))
	if err != 1 {
		return nil, errs.NewSerialisation("couldn't set bytes")
	}
	return &PlutoTritonScalar{
		V: *value,
		G: s.G,
	}, nil
}

func (s *PlutoTritonScalar) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) > impl2.WideFieldBytes {
		return nil, errs.NewLength("invalid length > %d", impl2.WideFieldBytes)
	}
	buffer := bitstring.PadToRight(bitstring.ReverseBytes(input), impl2.WideFieldBytes-len(input))
	value := new(impl2.Fq).SetBytesWide((*[impl2.WideFieldBytes]byte)(buffer))
	return &PlutoTritonScalar{
		V: *value,
		G: s.G,
	}, nil
}

func (s *PlutoTritonScalar) MarshalBinary() ([]byte, error) {
	res := impl.MarshalBinary(s.ScalarField().Curve().Name(), s.Bytes)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (s *PlutoTritonScalar) UnmarshalBinary(input []byte) error {
	sc, err := impl.UnmarshalBinary(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
	}
	ss, ok := sc.(*PlutoTritonScalar)
	if !ok {
		return errs.NewType("invalid base field element")
	}
	s.V = ss.V
	name, _, err := impl.ParseBinary(input)
	if err != nil {
		return errs.WrapSerialisation(err, "couldn't extract name from input")
	}
	switch name {
	case NamePluto:
		s.G = NewPluto()
	case NameTriton:
		s.G = NewTriton()
	default:
		return errs.NewType("name %s is not supported", name)
	}
	return nil
}

func (s *PlutoTritonScalar) MarshalJSON() ([]byte, error) {
	res, err := impl.MarshalJson(s.ScalarField().Curve().Name(), s.Bytes)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (s *PlutoTritonScalar) UnmarshalJSON(input []byte) error {
	name, _, err := impl.ParseJSON(input)
	if err != nil {
		return errs.WrapSerialisation(err, "couldn't extract name from input")
	}
	switch name {
	case NamePluto:
		s.G = NewPluto()
	case NameTriton:
		s.G = NewTriton()
	default:
		return errs.NewType("name %s is not supported", name)
	}
	sc, err := impl.UnmarshalJson(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract a base field element from json")
	}
	S, ok := sc.(*PlutoTritonScalar)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.V = S.V
	return nil
}
func (s *PlutoTritonScalar) HashCode() uint64 {
	return s.Uint64()
}
