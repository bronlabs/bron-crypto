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

var _ curves.Scalar = (*PallasScalar)(nil)
var _ encoding.BinaryMarshaler = (*PallasScalar)(nil)
var _ encoding.BinaryUnmarshaler = (*PallasScalar)(nil)
var _ json.Unmarshaler = (*PallasScalar)(nil)

type PallasScalar struct {
	V pastaImpl.Fq

	_ ds.Incomparable
}

func NewPallasScalar(value uint64) *PallasScalar {
	result := new(PallasScalar)
	result.V.SetUint64(value)
	return result
}

func (*PallasScalar) Structure() curves.ScalarField {
	return NewPallasScalarField()
}

func (s *PallasScalar) Unwrap() curves.Scalar {
	return s
}

func (*PallasScalar) Order(operator algebra.BinaryOperator[curves.Scalar]) (*saferith.Modulus, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) ApplyOp(operator algebra.BinaryOperator[curves.Scalar], x algebra.GroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) IsIdentity(under algebra.BinaryOperator[curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) Inverse(under algebra.BinaryOperator[curves.Scalar]) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) IsInverse(of algebra.GroupElement[curves.ScalarField, curves.Scalar], under algebra.BinaryOperator[curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) CoPrime(x curves.Scalar) bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) GCD(x curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) LCM(x curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) Factorise() []curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) EuclideanDiv(x curves.Scalar) (quotient curves.Scalar, reminder curves.Scalar) {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) IsTorsionElementUnderMultiplication(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) Lattice() algebra.OrderTheoreticLattice[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) Next() (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) Previous() (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) Chain() algebra.Chain[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) IsNonZero() bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) IsPositive() bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) Int() algebra.Int {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) FromInt(v algebra.Int) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) Not() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) And(x algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) ApplyAnd(x algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) IsConjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) Or(x algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) ApplyOr(x algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) IsDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) ApplyXor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) IsExclusiveDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) ExclusiveDisjunctiveInverse() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) IsExclusiveDisjunctiveInverse(of algebra.ExclusiveDisjunctiveGroupElement[curves.ScalarField, curves.Scalar]) bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) Lsh(bits uint) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) Rsh(bits uint) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) BytesLE() []byte {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) SetBytesLE(bytes []byte) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasScalar) SetBytesWideLE(bytes []byte) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (s *PallasScalar) Equal(rhs curves.Scalar) bool {
	rhse, ok := rhs.(*PallasScalar)
	if !ok {
		return false
	}

	return s.V.Equals(&rhse.V) == 1
}

func (s *PallasScalar) Clone() curves.Scalar {
	clone := new(PallasScalar)
	clone.V.Set(&s.V)
	return clone
}

// === Additive Groupoid Methods.

func (s *PallasScalar) Add(rhs algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*PallasScalar)
	if !ok {
		panic("rhs is not a pallas scalar")
	}

	result := new(PallasScalar)
	result.V.Add(&s.V, &r.V)
	return result
}

func (s *PallasScalar) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(PallasScalar).SetNat(n)
	return s.Add(x.Unwrap().Mul(reducedN))
}

func (s *PallasScalar) Double() curves.Scalar {
	return s.Add(s)
}

func (s *PallasScalar) Triple() curves.Scalar {
	return s.Double().Add(s)
}

// === Multiplicative Groupoid Methods.

func (s *PallasScalar) Mul(rhs algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*PallasScalar)
	if !ok {
		panic("rhs is not a pallas scalar")
	}

	result := new(PallasScalar)
	result.V.Mul(&s.V, &r.V)
	return result
}

func (s *PallasScalar) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	return s.Mul(x.Exp(n))
}

func (s *PallasScalar) Square() curves.Scalar {
	result := new(PallasScalar)
	result.V.Square(&s.V)
	return result
}

func (s *PallasScalar) Cube() curves.Scalar {
	return s.Square().Mul(s)
}

// === Additive Monoid Methods.

func (s *PallasScalar) IsAdditiveIdentity() bool {
	return s.V.IsZero() == 1
}

// === Multiplicative Monoid Methods.

func (s *PallasScalar) IsMultiplicativeIdentity() bool {
	return s.V.IsOne() == 1
}

// === Additive Group Methods.

func (s *PallasScalar) AdditiveInverse() curves.Scalar {
	result := new(PallasScalar)
	result.V.Neg(&s.V)
	return result
}

func (s *PallasScalar) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Add(of).IsAdditiveIdentity()
}

func (s *PallasScalar) Sub(rhs algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*PallasScalar)
	if !ok {
		panic("rhs is not a pallas scalar")
	}

	result := new(PallasScalar)
	result.V.Sub(&s.V, &r.V)
	return result
}

func (s *PallasScalar) ApplySub(x algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(PallasScalar).SetNat(n)
	return s.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (s *PallasScalar) MultiplicativeInverse() (curves.Scalar, error) {
	value := new(PallasScalar)
	wasInverted := value.V.Inv(&s.V)
	if wasInverted != 1 {
		return nil, errs.NewFailed("inverse doesn't exist")
	}

	return value, nil
}

func (s *PallasScalar) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Mul(of).IsMultiplicativeIdentity()
}

func (s *PallasScalar) Div(rhs algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	r, ok := rhs.(*PallasScalar)
	if !ok {
		return nil, errs.NewFailed("rhs is not a pallas scalar")
	}

	v := new(PallasScalar)
	wasInverted := v.V.Div(&s.V, &r.V)
	if wasInverted != 1 {
		return nil, errs.NewFailed("cannot invert rhs")
	}
	return v, nil
}

func (s *PallasScalar) ApplyDiv(x algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) (curves.Scalar, error) {
	return s.Div(x.Exp(n))
}

// === Ring Methods.

func (s *PallasScalar) IsQuadraticResidue() bool {
	_, err := s.Sqrt()
	return err != nil
}

func (s *PallasScalar) Sqrt() (curves.Scalar, error) {
	value := new(PallasScalar)
	wasSquare := value.V.Sqrt(&s.V)
	if wasSquare != 1 {
		return nil, errs.NewFailed("not a square")
	}
	return value, nil
}

func (s *PallasScalar) MulAdd(y algebra.RingElement[curves.ScalarField, curves.Scalar], z algebra.RingElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return s.Mul(y).Add(z)
}

// === Finite Field Methods.

func (s *PallasScalar) SubFieldElement(index uint) curves.Scalar {
	return s
}

func (s *PallasScalar) Norm() curves.Scalar {
	return s
}

// === Zp Methods.

func (s *PallasScalar) Exp(k *saferith.Nat) curves.Scalar {
	kBytes := k.Bytes()
	slices.Reverse(kBytes)

	value := new(PallasScalar)
	fieldsImpl.Pow(&value.V, &s.V, kBytes)
	return value
}

func (s *PallasScalar) Neg() curves.Scalar {
	return s.AdditiveInverse()
}

func (s *PallasScalar) IsZero() bool {
	return s.V.IsZero() == 1
}

func (s *PallasScalar) IsOne() bool {
	return s.V.IsOne() == 1
}

func (s *PallasScalar) IsOdd() bool {
	return (s.V.Bytes()[0] & 1) == 1
}

func (s *PallasScalar) IsEven() bool {
	return (s.V.Bytes()[0] & 1) == 0
}

func (s *PallasScalar) Increment() curves.Scalar {
	ee, ok := s.Add(s.ScalarField().One()).(*PallasScalar)
	if !ok {
		panic("invalid type")
	}
	return ee
}

func (s *PallasScalar) Decrement() curves.Scalar {
	ee, ok := s.Sub(s.ScalarField().One()).(*PallasScalar)
	if !ok {
		panic("invalid type")
	}
	return ee
}

// === Ordering Methods.

func (s *PallasScalar) Cmp(rhs algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) algebra.Ordering {
	r, ok := rhs.(*PallasScalar)
	if !ok {
		return algebra.Incomparable
	}

	return algebra.Ordering(ct.SliceCmpLE(s.V.Limbs(), r.V.Limbs()))
}

func (s *PallasScalar) IsBottom() bool {
	return s.IsZero()
}

func (s *PallasScalar) IsTop() bool {
	return s.Add(s.ScalarField().One()).IsZero()
}

func (s *PallasScalar) Join(rhs algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return s.Max(rhs.Unwrap())
}

func (s *PallasScalar) Max(rhs curves.Scalar) curves.Scalar {
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

func (s *PallasScalar) Meet(rhs algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return s.Min(rhs.Unwrap())
}

func (s *PallasScalar) Min(rhs curves.Scalar) curves.Scalar {
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

func (*PallasScalar) ScalarField() curves.ScalarField {
	return NewPallasScalarField()
}

// === Serialisation.

func (s *PallasScalar) Uint64() uint64 {
	return s.Nat().Big().Uint64()
}

func (*PallasScalar) SetNat(v *saferith.Nat) curves.Scalar {
	if v == nil {
		return nil
	}
	vReduced := new(saferith.Nat).Mod(v, pallasOrder)
	vBytes := vReduced.Bytes()
	slices.Reverse(vBytes)
	result := new(PallasScalar)
	ok := result.V.SetBytesWide(vBytes)
	if ok != 1 {
		panic("this should never happen")
	}
	return result
}

func (s *PallasScalar) Nat() *saferith.Nat {
	sBytes := s.V.Bytes()
	slices.Reverse(sBytes)
	return new(saferith.Nat).SetBytes(sBytes)
}

func (s *PallasScalar) Bytes() []byte {
	t := s.V.Bytes()
	slices.Reverse(t)
	return t
}

func (*PallasScalar) SetBytes(input []byte) (curves.Scalar, error) {
	if len(input) != pastaImpl.FqBytes {
		return nil, errs.NewLength("invalid length")
	}
	inputLE := bitstring.ReverseBytes(input)
	value := new(PallasScalar)
	ok := value.V.SetBytes(inputLE)
	if ok != 1 {
		return nil, errs.NewFailed("could not set bytes")
	}
	return value, nil
}

func (*PallasScalar) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) > pastaImpl.FqWideBytes {
		return nil, errs.NewLength("invalid length %d > %d bytes", len(input), pastaImpl.FqWideBytes)
	}
	input = bitstring.ReverseBytes(input)
	result := new(PallasScalar)
	ok := result.V.SetBytesWide(input)
	if ok != 1 {
		return nil, errs.NewFailed("could not set bytes")
	}
	return result, nil
}

func (s *PallasScalar) MarshalBinary() ([]byte, error) {
	res := curvesImpl.MarshalBinary(s.ScalarField().Curve().Name(), s.Bytes)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (s *PallasScalar) UnmarshalBinary(input []byte) error {
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
	ss, ok := sc.(*PallasScalar)
	if !ok {
		return errs.NewType("invalid base field element")
	}
	s.V.Set(&ss.V)
	return nil
}

func (s *PallasScalar) MarshalJSON() ([]byte, error) {
	res, err := curvesImpl.MarshalJson(s.ScalarField().Curve().Name(), s.Bytes)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (s *PallasScalar) UnmarshalJSON(input []byte) error {
	sc, err := curvesImpl.UnmarshalJson(s.ScalarField().Name(), s.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract a base field element from json")
	}
	S, ok := sc.(*PallasScalar)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.V.Set(&S.V)
	return nil
}

// === Misc.
func (s *PallasScalar) HashCode() uint64 {
	return s.Uint64()
}
