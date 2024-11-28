package k256

import (
	"encoding"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/arithmetic/limb4"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl/fq"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var _ curves.Scalar = (*Scalar)(nil)
var _ encoding.BinaryMarshaler = (*Scalar)(nil)
var _ encoding.BinaryUnmarshaler = (*Scalar)(nil)
var _ json.Unmarshaler = (*Scalar)(nil)

type Scalar struct {
	V *limb4.FieldValue

	_ ds.Incomparable
}

func NewScalar(value uint64) *Scalar {
	return &Scalar{
		V: fq.New().SetUint64(value),
	}
}

// === Basic Methods.

func (*Scalar) Structure() curves.ScalarField {
	return NewScalarField()
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
	return s.V.Equal(rhse.V) == 1
}

func (s *Scalar) Clone() curves.Scalar {
	return &Scalar{
		V: fq.New().Set(s.V),
	}
}

// === Additive Groupoid Methods.

func (s *Scalar) Add(rhs algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			V: fq.New().Add(s.V, r.V),
		}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *Scalar) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
	return s.Add(x.Unwrap().Mul(reducedN))
}

func (s *Scalar) Double() curves.Scalar {
	return &Scalar{
		V: fq.New().Double(s.V),
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
			V: fq.New().Mul(s.V, r.V),
		}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *Scalar) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	return s.Mul(x.Unwrap().Exp(n))
}

func (s *Scalar) Square() curves.Scalar {
	return &Scalar{
		V: fq.New().Square(s.V),
	}
}

func (s *Scalar) Cube() curves.Scalar {
	value := fq.New().Mul(s.V, s.V)
	value.Mul(value, s.V)
	return &Scalar{
		V: value,
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
		V: fq.New().Neg(s.V),
	}
}

func (s *Scalar) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Add(of).IsAdditiveIdentity()
}

func (s *Scalar) Sub(rhs algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			V: fq.New().Sub(s.V, r.V),
		}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *Scalar) ApplySub(x algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
	return s.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (s *Scalar) MultiplicativeInverse() (curves.Scalar, error) {
	value, wasInverted := fq.New().Invert(s.V)
	if !wasInverted {
		return nil, errs.NewFailed("inverse doesn't exist")
	}

	return &Scalar{
		V: value,
	}, nil
}

func (s *Scalar) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Mul(of).IsMultiplicativeIdentity()
}

func (s *Scalar) Div(rhs algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	r, ok := rhs.(*Scalar)
	if ok {
		v, wasInverted := fq.New().Invert(r.V)
		if !wasInverted {
			return nil, errs.NewFailed("cannot invert rhs")
		}
		v.Mul(v, s.V)
		return &Scalar{V: v}, nil
	} else {
		return nil, errs.NewFailed("rhs is not ScalarK256")
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
	value, wasSquare := fq.New().Sqrt(s.V)
	if !wasSquare {
		return nil, errs.NewFailed("not a square")
	}
	return &Scalar{
		V: value,
	}, nil
}

func (s *Scalar) MulAdd(p algebra.RingElement[curves.ScalarField, curves.Scalar], q algebra.RingElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return s.Mul(p).Add(q)
}

// === Finite Field Methods.

func (s *Scalar) SubFieldElement(index uint) curves.Scalar {
	return s
}

func (s *Scalar) Norm() curves.Scalar {
	return s
}

// === Zp Methods.

func (s *Scalar) Exp(e *saferith.Nat) curves.Scalar {
	exponent, ok := s.Structure().Element().SetNat(e).(*Scalar)
	if !ok {
		panic("rhs is not ScalarK256")
	}

	value := fq.New().Exp(s.V, exponent.V)
	return &Scalar{V: value}
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
	return s.V.Bytes()[0]&1 == 1
}

func (s *Scalar) IsEven() bool {
	return s.V.Bytes()[0]&1 == 0
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
		return algebra.Ordering(s.V.Cmp(r.V))
	} else {
		panic("rhs is not ScalarK256")
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

func (*Scalar) ScalarField() curves.ScalarField {
	return NewScalarField()
}

// === Serialisation.

func (s *Scalar) Uint64() uint64 {
	return s.Nat().Big().Uint64()
}

func (*Scalar) SetNat(v *saferith.Nat) curves.Scalar {
	if v == nil {
		return nil
	}
	value := fq.New().SetNat(v)
	return &Scalar{
		V: value,
	}
}

func (s *Scalar) Nat() *saferith.Nat {
	return s.V.Nat()
}

func (s *Scalar) Bytes() []byte {
	t := s.V.Bytes()
	return bitstring.ReverseBytes(t[:])
}

func (*Scalar) SetBytes(input []byte) (curves.Scalar, error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewLength("invalid length")
	}
	input = bitstring.ReverseBytes(input)
	value, err := fq.New().SetBytes((*[base.FieldBytes]byte)(input))
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set bytes")
	}
	return &Scalar{
		V: value,
	}, nil
}

func (*Scalar) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) > base.WideFieldBytes {
		return nil, errs.NewLength("invalid length (%d > %d bytes)", len(input), base.WideFieldBytes)
	}
	input = bitstring.PadToRight(bitstring.ReverseBytes(input), base.WideFieldBytes-len(input))
	return &Scalar{
		V: fq.New().SetBytesWide((*[base.WideFieldBytes]byte)(input)),
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
	name, _, err := impl.ParseBinary(input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract name from input")
	}
	if name != s.ScalarField().Name() {
		return errs.NewType("name %s is not supported", name)
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewType("invalid base field element")
	}
	s.V = ss.V
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
	sc, err := impl.UnmarshalJson(s.ScalarField().Name(), s.SetBytes, input)
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
