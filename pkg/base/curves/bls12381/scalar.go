package bls12381

import (
	"encoding"
	"encoding/json"
	"fmt"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	bls12381impl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/arithmetic/limb4"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

var _ curves.Scalar = (*Scalar)(nil)
var _ encoding.BinaryMarshaler = (*Scalar)(nil)
var _ encoding.BinaryUnmarshaler = (*Scalar)(nil)
var _ json.Unmarshaler = (*Scalar)(nil)

type Scalar struct {
	V *limb4.FieldValue
	G curves.Curve

	_ ds.Incomparable
}

func NewScalar(subgroup curves.Curve, value uint64) (*Scalar, error) {
	if subgroup.Name() != NewG1().Name() && subgroup.Name() != NewG2().Name() {
		return nil, errs.NewCurve("subgroup %s is not one of the bls source subgroups", subgroup.Name())
	}
	return &Scalar{
		V: bls12381impl.FqNew().SetUint64(value),
		G: subgroup,
	}, nil
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

func (s *Scalar) BytesLE() []byte {
	buffer := s.V.Bytes()
	return buffer[:]
}

func (s *Scalar) SetBytesLE(input []byte) (curves.Scalar, error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewLength("invalid length")
	}
	reducedInput := saferithUtils.NatFromBytesMod(input, r)
	buffer := bitstring.PadToLeft(reducedInput.Bytes(), base.FieldBytes-len(reducedInput.Bytes()))
	value, err := bls12381impl.FqNew().SetBytes((*[base.FieldBytes]byte)(buffer))
	if err != nil {
		return nil, errs.WrapSerialisation(err, "couldn't set bytes")
	}
	return &Scalar{
		V: value,
		G: s.G,
	}, nil
}

func (*Scalar) SetBytesWideLE(bytes []byte) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Scalar) Equal(rhs curves.Scalar) bool {
	return s.Cmp(rhs) == 0
}

func (s *Scalar) Clone() curves.Scalar {
	return &Scalar{
		V: bls12381impl.FqNew().Set(s.V),
		G: s.G,
	}
}

// === Additive Groupoid Methods.

func (s *Scalar) Add(rhs algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			V: bls12381impl.FqNew().Add(s.V, r.V),
			G: s.G,
		}
	} else {
		panic("rhs is not ScalarBls12381")
	}
}

func (s *Scalar) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n).(*Scalar)
	reducedN.G = s.G
	return s.Add(x.Unwrap().Mul(reducedN))
}

func (s *Scalar) Double() curves.Scalar {
	v := bls12381impl.FqNew().Double(s.V)
	return &Scalar{
		V: v,
		G: s.G,
	}
}

func (s *Scalar) Triple() curves.Scalar {
	return s.Double().Add(s)
}

// === Multiplicative Groupoid Methods.

func (s *Scalar) Mul(rhs algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			V: bls12381impl.FqNew().Mul(s.V, r.V),
			G: s.G,
		}
	} else {
		panic("rhs is not ScalarBls12381")
	}
}

func (s *Scalar) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	return s.Mul(x.Exp(n))
}

func (s *Scalar) Square() curves.Scalar {
	return &Scalar{
		V: bls12381impl.FqNew().Square(s.V),
		G: s.G,
	}
}

func (s *Scalar) Cube() curves.Scalar {
	value := bls12381impl.FqNew().Square(s.V)
	value.Mul(value, s.V)
	return &Scalar{
		V: value,
		G: s.G,
	}
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
	return &Scalar{
		V: bls12381impl.FqNew().Neg(s.V),
		G: s.G,
	}
}

func (s *Scalar) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Add(of).IsAdditiveIdentity()
}

func (s *Scalar) Sub(rhs algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			V: bls12381impl.FqNew().Sub(s.V, r.V),
			G: s.G,
		}
	} else {
		panic("rhs is not ScalarBls12381")
	}
}

func (s *Scalar) ApplySub(x algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n).(*Scalar)
	reducedN.G = s.G
	return s.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (s *Scalar) MultiplicativeInverse() (curves.Scalar, error) {
	value, wasInverted := bls12381impl.FqNew().Invert(s.V)
	if !wasInverted {
		return nil, errs.NewFailed("inverse doesn't exist")
	}

	return &Scalar{
		V: value,
		G: s.G,
	}, nil
}

func (s *Scalar) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Mul(of).IsMultiplicativeIdentity()
}

func (s *Scalar) Div(rhs algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	r, ok := rhs.(*Scalar)
	if ok {
		v, wasInverted := bls12381impl.FqNew().Invert(r.V)
		if !wasInverted {
			return nil, errs.NewFailed("cannot invert scalar")
		}
		v.Mul(v, s.V)
		return &Scalar{
			V: v,
			G: s.G,
		}, nil
	} else {
		return nil, errs.NewFailed("rhs is not ScalarBls12381")
	}
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
	value, wasSquare := bls12381impl.FqNew().Sqrt(s.V)
	if !wasSquare {
		return nil, errs.NewFailed("not a square")
	}
	return &Scalar{
		V: value,
		G: s.G,
	}, nil
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
	exp, ok := s.Structure().Element().SetNat(k).(*Scalar)
	if !ok {
		panic("rhs is not ScalarBls12381")
	}

	value := bls12381impl.FqNew().Exp(s.V, exp.V)
	return &Scalar{
		V: value,
		G: s.G,
	}
}

func (s *Scalar) Neg() curves.Scalar {
	return s.AdditiveInverse()
}

func (s *Scalar) IsZero() bool {
	return s.V.IsZero() == 1
}

func (s *Scalar) IsOne() bool {
	return s.V.IsOne() == 1
}

func (s *Scalar) IsOdd() bool {
	bytes_ := s.V.Bytes()
	return bytes_[0]&1 == 1
}

func (s *Scalar) IsEven() bool {
	bytes_ := s.V.Bytes()
	return bytes_[0]&1 == 0
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
	r, ok := rhs.(*Scalar)
	if ok {
		// TODO: debug Cmp for BLS
		gt, eq, lt := s.Nat().Cmp(r.Nat())
		if gt == 1 {
			return 1
		}
		if eq == 1 {
			return 0
		}
		if lt == 1 {
			return -1
		}
		return algebra.Incomparable
	} else {
		return algebra.Incomparable
	}
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
	return &Scalar{
		V: bls12381impl.FqNew().SetNat(v),
		G: s.G,
	}
}

func (s *Scalar) Nat() *saferith.Nat {
	return s.V.Nat()
}

func (s *Scalar) Bytes() []byte {
	t := s.V.Bytes()
	return bitstring.ReverseBytes(t[:])
}

func (s *Scalar) SetBytes(input []byte) (curves.Scalar, error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewLength("invalid length")
	}
	reducedInput := saferithUtils.NatFromBytesMod(input, r)
	buffer := bitstring.PadToRight(bitstring.ReverseBytes(reducedInput.Bytes()), base.FieldBytes-len(reducedInput.Bytes()))
	value, err := bls12381impl.FqNew().SetBytes((*[base.FieldBytes]byte)(buffer))
	if err != nil {
		return nil, errs.WrapSerialisation(err, "couldn't set bytes")
	}
	return &Scalar{
		V: value,
		G: s.G,
	}, nil
}

func (s *Scalar) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) > base.WideFieldBytes {
		return nil, errs.NewLength("invalid length > %d", base.WideFieldBytes)
	}
	buffer := bitstring.PadToRight(bitstring.ReverseBytes(input), base.WideFieldBytes-len(input))
	value := bls12381impl.FqNew().SetBytesWide((*[base.WideFieldBytes]byte)(buffer))
	return &Scalar{
		V: value,
		G: s.G,
	}, nil
}

func (s *Scalar) MarshalBinary() ([]byte, error) {
	res := impl.MarshalBinary(s.ScalarField().Curve().Name(), s.Bytes)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (s *Scalar) UnmarshalBinary(input []byte) error {
	sc, err := impl.UnmarshalBinary(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewType("invalid base field element")
	}
	s.V = ss.V
	name, _, err := impl.ParseBinary(input)
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
	res, err := impl.MarshalJson(s.ScalarField().Curve().Name(), s.Bytes)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (s *Scalar) UnmarshalJSON(input []byte) error {
	name, _, err := impl.ParseJSON(input)
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
	sc, err := impl.UnmarshalJson(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract a base field element from json")
	}
	S, ok := sc.(*Scalar)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.V = S.V
	return nil
}
func (s *Scalar) HashCode() uint64 {
	return s.Uint64()
}
