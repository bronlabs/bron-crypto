package bls12381

import (
	"encoding"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base/algebra"
	"github.com/bronlabs/krypton-primitives/pkg/base/bitstring"
	"github.com/bronlabs/krypton-primitives/pkg/base/ct"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	bls12381Impl "github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381/impl"
	curvesImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl"
	fieldsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

var _ curves.Scalar = (*Scalar)(nil)
var _ encoding.BinaryMarshaler = (*Scalar)(nil)
var _ encoding.BinaryUnmarshaler = (*Scalar)(nil)
var _ json.Unmarshaler = (*Scalar)(nil)

type Scalar struct {
	G curves.Curve
	V bls12381Impl.Fq

	_ ds.Incomparable
}

func NewScalar(subgroup curves.Curve, value uint64) (*Scalar, error) {
	if subgroup.Name() != NewG1().Name() && subgroup.Name() != NewG2().Name() {
		return nil, errs.NewCurve("subgroup %s is not one of the bls source subgroups", subgroup.Name())
	}

	result := &Scalar{
		G: subgroup,
	}
	result.V.SetUint64(value)
	return result, nil
}

func (s *Scalar) Structure() curves.ScalarField {
	if s.G.Name() == NewG1().Name() {
		return NewScalarFieldG1()
	} else if s.G.Name() == NewG2().Name() {
		return NewScalarFieldG2()
	} else {
		panic("invalid scalar")
	}
}

func (s *Scalar) Unwrap() curves.Scalar {
	return s
}

func (*Scalar) Order(operator algebra.BinaryOperator[curves.Scalar]) (*saferith.Modulus, error) {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) ApplyOp(operator algebra.BinaryOperator[curves.Scalar], x algebra.GroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) IsIdentity(under algebra.BinaryOperator[curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) Inverse(under algebra.BinaryOperator[curves.Scalar]) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) IsInverse(of algebra.GroupElement[curves.ScalarField, curves.Scalar], under algebra.BinaryOperator[curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.Scalar]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) CoPrime(x curves.Scalar) bool {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) GCD(x curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) LCM(x curves.Scalar) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) Factorise() []curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) EuclideanDiv(x curves.Scalar) (quotient curves.Scalar, reminder curves.Scalar) {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) IsTorsionElementUnderMultiplication(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) Lattice() algebra.OrderTheoreticLattice[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) Next() (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) Previous() (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) Chain() algebra.Chain[curves.ScalarField, curves.Scalar] {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) IsNonZero() bool {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) IsPositive() bool {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) Int() algebra.Int {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) FromInt(v algebra.Int) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) Not() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) And(x algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) ApplyAnd(x algebra.ConjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) IsConjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) Or(x algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) ApplyOr(x algebra.DisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) IsDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) ApplyXor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) IsExclusiveDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) ExclusiveDisjunctiveInverse() curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) IsExclusiveDisjunctiveInverse(of algebra.ExclusiveDisjunctiveGroupElement[curves.ScalarField, curves.Scalar]) bool {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) Lsh(bits uint) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) Rsh(bits uint) curves.Scalar {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) BytesLE() []byte {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) SetBytesLE(bytes []byte) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) SetBytesWideLE(bytes []byte) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Scalar) Equal(rhs curves.Scalar) bool {
	rhse, ok := rhs.(*Scalar)
	if !ok {
		return false
	}

	return s.V.Equals(&rhse.V) == 1
}

func (s *Scalar) Clone() curves.Scalar {
	result := &Scalar{G: s.G}
	result.V.Set(&s.V)
	return result
}

// === Additive Groupoid Methods.

func (s *Scalar) Add(rhs algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if !ok {
		panic("rhs is not ScalarBls12381")
	}

	result := &Scalar{G: s.G}
	result.V.Add(&s.V, &r.V)
	return result
}

func (s *Scalar) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n).(*Scalar)
	reducedN.G = s.G
	return s.Add(x.Unwrap().Mul(reducedN))
}

func (s *Scalar) Double() curves.Scalar {
	return s.Add(s)
}

func (s *Scalar) Triple() curves.Scalar {
	return s.Double().Add(s)
}

// === Multiplicative Groupoid Methods.

func (s *Scalar) Mul(rhs algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if !ok {
		panic("rhs is not ScalarBls12381")
	}

	result := &Scalar{G: s.G}
	result.V.Mul(&s.V, &r.V)
	return result
}

func (s *Scalar) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	return s.Mul(x.Exp(n))
}

func (s *Scalar) Square() curves.Scalar {
	result := &Scalar{G: s.G}
	result.V.Square(&s.V)
	return result
}

func (s *Scalar) Cube() curves.Scalar {
	return s.Square().Mul(s)
}

// === Additive Monoid Methods.

func (s *Scalar) IsAdditiveIdentity() bool {
	return s.V.IsZero() == 1
}

// === Multiplicative Monoid Methods.

func (s *Scalar) IsMultiplicativeIdentity() bool {
	return s.V.IsOne() == 1
}

// === Additive Group Methods.

func (s *Scalar) AdditiveInverse() curves.Scalar {
	result := &Scalar{G: s.G}
	result.V.Neg(&result.V)
	return result
}

func (s *Scalar) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Add(of).IsAdditiveIdentity()
}

func (s *Scalar) Sub(rhs algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if !ok {
		panic("rhs is not ScalarBls12381")
	}

	result := &Scalar{G: s.G}
	result.V.Sub(&s.V, &r.V)
	return result
}

func (s *Scalar) ApplySub(x algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n).(*Scalar)
	reducedN.G = s.G
	return s.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (s *Scalar) MultiplicativeInverse() (curves.Scalar, error) {
	value := &Scalar{G: s.G}
	wasInverted := value.V.Inv(&s.V)
	if wasInverted != 1 {
		return nil, errs.NewFailed("inverse doesn't exist")
	}

	return value, nil
}

func (s *Scalar) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Mul(of).IsMultiplicativeIdentity()
}

func (s *Scalar) Div(rhs algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	rhse, ok := rhs.(*Scalar)
	if !ok {
		return nil, errs.NewFailed("rhs is not ScalarBls12381")
	}

	v := &Scalar{G: s.G}
	wasInverted := v.V.Div(&s.V, &rhse.V)
	if wasInverted != 1 {
		return nil, errs.NewFailed("cannot invert scalar")
	}

	return v, nil
}

func (s *Scalar) ApplyDiv(x algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) (curves.Scalar, error) {
	return s.Div(x.Exp(n))
}

// === Ring Methods.

func (s *Scalar) IsQuadraticResidue() bool {
	_, err := s.Sqrt()
	return err != nil
}

func (s *Scalar) Sqrt() (curves.Scalar, error) {
	value := &Scalar{G: s.G}
	wasSquare := value.V.Sqrt(&s.V)
	if wasSquare != 1 {
		return nil, errs.NewFailed("not a square")
	}

	return value, nil
}

func (s *Scalar) MulAdd(y algebra.RingElement[curves.ScalarField, curves.Scalar], z algebra.RingElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return s.Mul(y).Add(z)
}

// === Finite Field Methods.

func (s *Scalar) SubFieldElement(index uint) curves.Scalar {
	return s
}

func (s *Scalar) Norm() curves.Scalar {
	return s
}

// === Zp Methods.

func (s *Scalar) Exp(k *saferith.Nat) curves.Scalar {
	eBytes := k.Bytes()
	slices.Reverse(eBytes)

	value := &Scalar{G: s.G}
	fieldsImpl.Pow(&value.V, &s.V, eBytes)
	return value
}

func (s *Scalar) Neg() curves.Scalar {
	result := &Scalar{G: s.G}
	result.V.Neg(&s.V)
	return result
}

func (s *Scalar) IsZero() bool {
	return s.V.IsZero() == 1
}

func (s *Scalar) IsOne() bool {
	return s.V.IsOne() == 1
}

func (s *Scalar) IsOdd() bool {
	data := s.V.Bytes()
	return data[0]&1 == 1
}

func (s *Scalar) IsEven() bool {
	data := s.V.Bytes()
	return data[0]&1 == 0
}

func (s *Scalar) Increment() curves.Scalar {
	ee, ok := s.Add(s.ScalarField().One()).(*Scalar)
	if !ok {
		panic("invalid type")
	}
	return ee
}

func (s *Scalar) Decrement() curves.Scalar {
	ee, ok := s.Sub(s.ScalarField().One()).(*Scalar)
	if !ok {
		panic("invalid type")
	}
	return ee
}

// === Ordering Methods.

func (s *Scalar) Cmp(rhs algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) algebra.Ordering {
	rhse, ok := rhs.(*Scalar)
	if !ok {
		return algebra.Incomparable
	}

	return algebra.Ordering(ct.SliceCmpLE(s.V.Limbs(), rhse.V.Limbs()))
}

func (s *Scalar) IsBottom() bool {
	return s.IsZero()
}

func (s *Scalar) IsTop() bool {
	return s.Add(s.ScalarField().One()).IsZero()
}

func (s *Scalar) Join(rhs algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return s.Max(rhs.Unwrap())
}

func (s *Scalar) Max(rhs curves.Scalar) curves.Scalar {
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

func (s *Scalar) Meet(rhs algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return s.Min(rhs.Unwrap())
}

func (s *Scalar) Min(rhs curves.Scalar) curves.Scalar {
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

func (s *Scalar) ScalarField() curves.ScalarField {
	switch s.G.Name() {
	case NewG1().Name():
		return NewScalarFieldG1()
	case NewG2().Name():
		return NewScalarFieldG2()
	default:
		panic(fmt.Sprintf("subgroup %s is not a bls source subgroup", s.G.Name()))
	}
}

// === Serialisation.

func (s *Scalar) Uint64() uint64 {
	return s.Nat().Big().Uint64()
}

func (s *Scalar) SetNat(v *saferith.Nat) curves.Scalar {
	if v == nil {
		return nil
	}

	natReduces := new(saferith.Nat).Mod(v, bls12381SubGroupOrder)
	natBytes := natReduces.Bytes()
	slices.Reverse(natBytes)
	result := &Scalar{G: s.G}
	ok := result.V.SetBytesWide(natBytes)
	if ok != 1 {
		panic("this should never happer")
	}

	return result
}

func (s *Scalar) Nat() *saferith.Nat {
	sBytes := s.V.Bytes()
	slices.Reverse(sBytes)
	return new(saferith.Nat).SetBytes(sBytes)
}

func (s *Scalar) Bytes() []byte {
	t := s.V.Bytes()
	slices.Reverse(t)
	return t
}

func (s *Scalar) SetBytes(input []byte) (curves.Scalar, error) {
	if len(input) != bls12381Impl.FqBytes {
		return nil, errs.NewLength("invalid length")
	}

	buffer := bitstring.ReverseBytes(input)
	value := &Scalar{G: s.G}
	ok := value.V.SetBytes(buffer)
	if ok != 1 {
		return nil, errs.NewSerialisation("couldn't set bytes")
	}
	return value, nil
}

func (s *Scalar) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) > bls12381Impl.FqWideBytes {
		return nil, errs.NewLength("invalid length > %d", bls12381Impl.FqWideBytes)
	}

	buffer := bitstring.ReverseBytes(input)
	value := &Scalar{G: s.G}
	ok := value.V.SetBytesWide(buffer)
	if ok != 1 {
		panic("this should never happer")
	}

	return value, nil
}

func (s *Scalar) MarshalBinary() ([]byte, error) {
	res := curvesImpl.MarshalBinary(s.ScalarField().Curve().Name(), s.Bytes)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (s *Scalar) UnmarshalBinary(input []byte) error {
	sc, err := curvesImpl.UnmarshalBinary(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewType("invalid base field element")
	}
	s.V.Set(&ss.V)
	name, _, err := curvesImpl.ParseBinary(input)
	if err != nil {
		return errs.WrapSerialisation(err, "couldn't extract name from input")
	}
	switch name {
	case NameG1:
		s.G = NewG1()
	case NameG2:
		s.G = NewG2()
	default:
		return errs.NewType("name %s is not supported", name)
	}
	return nil
}

func (s *Scalar) MarshalJSON() ([]byte, error) {
	res, err := curvesImpl.MarshalJson(s.ScalarField().Curve().Name(), s.Bytes)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (s *Scalar) UnmarshalJSON(input []byte) error {
	name, _, err := curvesImpl.ParseJSON(input)
	if err != nil {
		return errs.WrapSerialisation(err, "couldn't extract name from input")
	}
	switch name {
	case NameG1:
		s.G = NewG1()
	case NameG2:
		s.G = NewG2()
	default:
		return errs.NewType("name %s is not supported", name)
	}
	sc, err := curvesImpl.UnmarshalJson(name, s.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract a base field element from json")
	}
	S, ok := sc.(*Scalar)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.V.Set(&S.V)
	return nil
}

func (s *Scalar) HashCode() uint64 {
	return s.Uint64()
}
