package pasta

import (
	"encoding"
	"encoding/json"
	"slices"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base/algebra"
	"github.com/bronlabs/krypton-primitives/pkg/base/bitstring"
	"github.com/bronlabs/krypton-primitives/pkg/base/ct"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	curvesImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl"
	fieldsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields"
	pastaImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/pasta/impl"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

var _ curves.Scalar = (*VestaScalar)(nil)
var _ encoding.BinaryMarshaler = (*VestaScalar)(nil)
var _ encoding.BinaryUnmarshaler = (*VestaScalar)(nil)
var _ json.Unmarshaler = (*VestaScalar)(nil)

type VestaScalar struct {
	V pastaImpl.Fp

	_ ds.Incomparable
}

func NewVestaScalar(value uint64) *VestaScalar {
	result := new(VestaScalar)
	result.V.SetUint64(value)
	return result
}

func (*VestaScalar) Structure() curves.ScalarField {
	return NewVestaScalarField()
}

func (s *VestaScalar) Unwrap() curves.Scalar {
	return s
}

func (*VestaScalar) Order(operator algebra.BinaryOperator[curves.Scalar]) (*saferith.Modulus, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) ApplyOp(operator algebra.BinaryOperator[curves.Scalar], x algebra.GroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) IsIdentity(under algebra.BinaryOperator[curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) Inverse(under algebra.BinaryOperator[curves.Scalar]) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) IsInverse(of algebra.GroupElement[curves.ScalarField, curves.Scalar], under algebra.BinaryOperator[curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) CoPrime(x curves.Scalar) bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) GCD(x curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) LCM(x curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) Factorise() []curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) EuclideanDiv(x curves.Scalar) (quotient curves.Scalar, reminder curves.Scalar) {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) IsTorsionElementUnderMultiplication(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) Lattice() algebra.OrderTheoreticLattice[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) Next() (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) Previous() (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) Chain() algebra.Chain[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) IsNonZero() bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) IsPositive() bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) Int() algebra.Int {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) FromInt(v algebra.Int) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) Not() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) And(x algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) ApplyAnd(x algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) IsConjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) Or(x algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) ApplyOr(x algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) IsDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) ApplyXor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) IsExclusiveDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) ExclusiveDisjunctiveInverse() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) IsExclusiveDisjunctiveInverse(of algebra.ExclusiveDisjunctiveGroupElement[curves.ScalarField, curves.Scalar]) bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) Lsh(bits uint) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) Rsh(bits uint) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) BytesLE() []byte {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) SetBytesLE(bytes []byte) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaScalar) SetBytesWideLE(bytes []byte) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (s *VestaScalar) Equal(rhs curves.Scalar) bool {
	rhse, ok := rhs.(*VestaScalar)
	if !ok {
		return false
	}

	return s.V.Equals(&rhse.V) == 1
}

func (s *VestaScalar) Clone() curves.Scalar {
	clone := new(VestaScalar)
	clone.V.Set(&s.V)
	return clone
}

// === Additive Groupoid Methods.

func (s *VestaScalar) Add(rhs algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*VestaScalar)
	if !ok {
		panic("rhs is not a vesta scalar")
	}

	result := new(VestaScalar)
	result.V.Add(&s.V, &r.V)
	return result
}

func (s *VestaScalar) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(VestaScalar).SetNat(n)
	return s.Add(x.Unwrap().Mul(reducedN))
}

func (s *VestaScalar) Double() curves.Scalar {
	return s.Add(s)
}

func (s *VestaScalar) Triple() curves.Scalar {
	return s.Double().Add(s)
}

// === Multiplicative Groupoid Methods.

func (s *VestaScalar) Mul(rhs algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*VestaScalar)
	if !ok {
		panic("rhs is not a vesta scalar")
	}

	result := new(VestaScalar)
	result.V.Mul(&s.V, &r.V)
	return result
}

func (s *VestaScalar) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	return s.Mul(x.Exp(n))
}

func (s *VestaScalar) Square() curves.Scalar {
	result := new(VestaScalar)
	result.V.Square(&s.V)
	return result
}

func (s *VestaScalar) Cube() curves.Scalar {
	return s.Square().Mul(s)
}

// === Additive Monoid Methods.

func (s *VestaScalar) IsAdditiveIdentity() bool {
	return s.V.IsZero() == 1
}

// === Multiplicative Monoid Methods.

func (s *VestaScalar) IsMultiplicativeIdentity() bool {
	return s.V.IsOne() == 1
}

// === Additive Group Methods.

func (s *VestaScalar) AdditiveInverse() curves.Scalar {
	result := new(VestaScalar)
	result.V.Neg(&s.V)
	return result
}

func (s *VestaScalar) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Add(of).IsAdditiveIdentity()
}

func (s *VestaScalar) Sub(rhs algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*VestaScalar)
	if !ok {
		panic("rhs is not a vesta scalar")
	}

	result := new(VestaScalar)
	result.V.Sub(&s.V, &r.V)
	return result
}

func (s *VestaScalar) ApplySub(x algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(VestaScalar).SetNat(n)
	return s.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (s *VestaScalar) MultiplicativeInverse() (curves.Scalar, error) {
	value := new(VestaScalar)
	wasInverted := value.V.Inv(&s.V)
	if wasInverted != 1 {
		return nil, errs.NewFailed("inverse doesn't exist")
	}

	return value, nil
}

func (s *VestaScalar) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Mul(of).IsMultiplicativeIdentity()
}

func (s *VestaScalar) Div(rhs algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	r, ok := rhs.(*VestaScalar)
	if !ok {
		return nil, errs.NewFailed("rhs is not a vesta scalar")
	}

	v := new(VestaScalar)
	wasInverted := v.V.Div(&s.V, &r.V)
	if wasInverted != 1 {
		return nil, errs.NewFailed("cannot invert rhs")
	}
	return v, nil
}

func (s *VestaScalar) ApplyDiv(x algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) (curves.Scalar, error) {
	return s.Div(x.Exp(n))
}

// === Ring Methods.

func (s *VestaScalar) IsQuadraticResidue() bool {
	_, err := s.Sqrt()
	return err != nil
}

func (s *VestaScalar) Sqrt() (curves.Scalar, error) {
	value := new(VestaScalar)
	wasSquare := value.V.Sqrt(&s.V)
	if wasSquare != 1 {
		return nil, errs.NewFailed("not a square")
	}
	return value, nil
}

func (s *VestaScalar) MulAdd(y algebra.RingElement[curves.ScalarField, curves.Scalar], z algebra.RingElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return s.Mul(y).Add(z)
}

// === Finite Field Methods.

func (s *VestaScalar) SubFieldElement(index uint) curves.Scalar {
	return s
}

func (s *VestaScalar) Norm() curves.Scalar {
	return s
}

// === Zp Methods.

func (s *VestaScalar) Exp(k *saferith.Nat) curves.Scalar {
	kBytes := k.Bytes()
	slices.Reverse(kBytes)

	value := new(VestaScalar)
	fieldsImpl.Pow(&value.V, &s.V, kBytes)
	return value
}

func (s *VestaScalar) Neg() curves.Scalar {
	return s.AdditiveInverse()
}

func (s *VestaScalar) IsZero() bool {
	return s.V.IsZero() == 1
}

func (s *VestaScalar) IsOne() bool {
	return s.V.IsOne() == 1
}

func (s *VestaScalar) IsOdd() bool {
	return (s.V.Bytes()[0] & 1) == 1
}

func (s *VestaScalar) IsEven() bool {
	return (s.V.Bytes()[0] & 1) == 0
}

func (s *VestaScalar) Increment() curves.Scalar {
	ee, ok := s.Add(s.ScalarField().One()).(*VestaScalar)
	if !ok {
		panic("invalid type")
	}
	return ee
}

func (s *VestaScalar) Decrement() curves.Scalar {
	ee, ok := s.Sub(s.ScalarField().One()).(*VestaScalar)
	if !ok {
		panic("invalid type")
	}
	return ee
}

// === Ordering Methods.

func (s *VestaScalar) Cmp(rhs algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) algebra.Ordering {
	r, ok := rhs.(*VestaScalar)
	if !ok {
		return algebra.Incomparable
	}

	return algebra.Ordering(ct.SliceCmpLE(s.V.Limbs(), r.V.Limbs()))
}

func (s *VestaScalar) IsBottom() bool {
	return s.IsZero()
}

func (s *VestaScalar) IsTop() bool {
	return s.Add(s.ScalarField().One()).IsZero()
}

func (s *VestaScalar) Join(rhs algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return s.Max(rhs.Unwrap())
}

func (s *VestaScalar) Max(rhs curves.Scalar) curves.Scalar {
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

func (s *VestaScalar) Meet(rhs algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return s.Min(rhs.Unwrap())
}

func (s *VestaScalar) Min(rhs curves.Scalar) curves.Scalar {
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

func (*VestaScalar) ScalarField() curves.ScalarField {
	return NewVestaScalarField()
}

// === Serialisation.

func (s *VestaScalar) Uint64() uint64 {
	return s.Nat().Big().Uint64()
}

func (*VestaScalar) SetNat(v *saferith.Nat) curves.Scalar {
	if v == nil {
		return nil
	}
	vReduced := new(saferith.Nat).Mod(v, vestaOrder)
	vBytes := vReduced.Bytes()
	slices.Reverse(vBytes)
	result := new(VestaScalar)
	ok := result.V.SetBytesWide(vBytes)
	if ok != 1 {
		panic("this should never happen")
	}
	return result
}

func (s *VestaScalar) Nat() *saferith.Nat {
	sBytes := s.V.Bytes()
	slices.Reverse(sBytes)
	return new(saferith.Nat).SetBytes(sBytes)
}

func (s *VestaScalar) Bytes() []byte {
	t := s.V.Bytes()
	slices.Reverse(t)
	return t
}

func (*VestaScalar) SetBytes(input []byte) (curves.Scalar, error) {
	if len(input) != pastaImpl.FpBytes {
		return nil, errs.NewLength("invalid length")
	}
	inputLE := bitstring.ReverseBytes(input)
	value := new(VestaScalar)
	ok := value.V.SetBytes(inputLE)
	if ok != 1 {
		return nil, errs.NewFailed("could not set bytes")
	}
	return value, nil
}

func (*VestaScalar) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) > pastaImpl.FpWideBytes {
		return nil, errs.NewLength("invalid length %d > %d bytes", len(input), pastaImpl.FpWideBytes)
	}
	input = bitstring.ReverseBytes(input)
	result := new(VestaScalar)
	ok := result.V.SetBytesWide(input)
	if ok != 1 {
		return nil, errs.NewFailed("could not set bytes")
	}
	return result, nil
}

func (s *VestaScalar) MarshalBinary() ([]byte, error) {
	res := curvesImpl.MarshalBinary(s.ScalarField().Curve().Name(), s.Bytes)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (s *VestaScalar) UnmarshalBinary(input []byte) error {
	sc, err := curvesImpl.UnmarshalBinary(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
	}
	name, _, err := curvesImpl.ParseBinary(input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract name from input")
	}
	if name != s.ScalarField().Name() {
		return errs.NewType("name %s is not supported", name)
	}
	ss, ok := sc.(*VestaScalar)
	if !ok {
		return errs.NewType("invalid base field element")
	}
	s.V.Set(&ss.V)
	return nil
}

func (s *VestaScalar) MarshalJSON() ([]byte, error) {
	res, err := curvesImpl.MarshalJson(s.ScalarField().Curve().Name(), s.Bytes)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (s *VestaScalar) UnmarshalJSON(input []byte) error {
	sc, err := curvesImpl.UnmarshalJson(s.ScalarField().Name(), s.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract a base field element from json")
	}
	S, ok := sc.(*VestaScalar)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.V.Set(&S.V)
	return nil
}

// === Misc.
func (s *VestaScalar) HashCode() uint64 {
	return s.Uint64()
}
