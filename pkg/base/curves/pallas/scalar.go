package pallas

import (
	"encoding"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas/impl/fq"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

var _ curves.Scalar = (*Scalar)(nil)
var _ encoding.BinaryMarshaler = (*Scalar)(nil)
var _ encoding.BinaryUnmarshaler = (*Scalar)(nil)
var _ json.Unmarshaler = (*Scalar)(nil)

type Scalar struct {
	integer.Number[curves.Scalar]
	algebra.BoundedOrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]
	V *fq.Fq

	_ ds.Incomparable
}

func (*Scalar) Mod(m integer.NaturalSemiRingElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	panic("implement me")
}
func (s *Scalar) Abs() curves.Scalar {
	return s
}
func NewScalar(value uint64) *Scalar {
	return &Scalar{
		V: new(fq.Fq).SetUint64(value),
	}
}

func (*Scalar) Structure() curves.ScalarField {
	return NewScalarField()
}

func (s *Scalar) Unwrap() curves.Scalar {
	return s
}

func (*Scalar) Operate(op algebra.Operator, rhs algebra.GroupoidElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	panic("implement me")
}
func (*Scalar) IsInvolution(under algebra.Operator) (bool, error) {
	panic("implement me")
}
func (*Scalar) IsInvolutionUnderAddition() bool {
	panic("implement me")
}
func (*Scalar) IsInvolutionUnderMultiplication() bool {
	panic("implement me")
}
func (*Scalar) CanGenerateAllElements(under algebra.Operator) bool {
	panic("implement me")
}
func (*Scalar) Order(operator algebra.Operator) (*saferith.Nat, error) {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) Apply(operator algebra.Operator, x algebra.GroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) IsIdentity(under algebra.Operator) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) Inverse(under algebra.Operator) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) IsInverse(of algebra.GroupElement[curves.ScalarField, curves.Scalar], under algebra.Operator) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) IsTorsionElement(order *saferith.Modulus, under algebra.Operator) (bool, error) {
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

// func (*Scalar) Int() integer.Int {
// 	//TODO implement me
// 	panic("implement me")
// }

// func (*Scalar) FromInt(v integer.Int) curves.Scalar {
// 	//TODO implement me
// 	panic("implement me")
// }

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
	return s.Cmp(rhs) == 0
}

func (s *Scalar) Clone() curves.Scalar {
	return &Scalar{
		V: new(fq.Fq).Set(s.V),
	}
}

// === Additive Groupoid Methods.

func (s *Scalar) Add(rhs algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			V: new(fq.Fq).Add(s.V, r.V),
		}
	} else {
		panic("rhs is not a pallas scalar")
	}
}

func (s *Scalar) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
	return s.Add(x.Unwrap().Mul(reducedN))
}

func (s *Scalar) Double() curves.Scalar {
	return &Scalar{
		V: new(fq.Fq).Double(s.V),
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
			V: new(fq.Fq).Mul(s.V, r.V),
		}
	} else {
		panic("rhs is not a pallas scalar")
	}
}

func (s *Scalar) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	return s.Mul(x.Exp(n))
}

func (s *Scalar) Square() curves.Scalar {
	return &Scalar{
		V: new(fq.Fq).Square(s.V),
	}
}

func (s *Scalar) Cube() curves.Scalar {
	value := new(fq.Fq).Mul(s.V, s.V)
	value.Mul(value, s.V)
	return &Scalar{
		V: value,
	}
}

// === Additive Monoid Methods.

func (s *Scalar) IsAdditiveIdentity() bool {
	return s.V.IsZero()
}

// === Multiplicative Monoid Methods.

func (s *Scalar) IsMultiplicativeIdentity() bool {
	return s.V.IsOne()
}

// === Additive Group Methods.

func (s *Scalar) AdditiveInverse() curves.Scalar {
	return &Scalar{
		V: new(fq.Fq).Neg(s.V),
	}
}

func (s *Scalar) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Add(of).IsAdditiveIdentity()
}

func (s *Scalar) Sub(rhs algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			V: new(fq.Fq).Sub(s.V, r.V),
		}
	} else {
		panic("rhs is not a pallas scalar")
	}
}

func (s *Scalar) ApplySub(x algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
	return s.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (s *Scalar) MultiplicativeInverse() (curves.Scalar, error) {
	value, wasInverted := new(fq.Fq).Invert(s.V)
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
		v, wasInverted := new(fq.Fq).Invert(r.V)
		if !wasInverted {
			return nil, errs.NewFailed("cannot invert rhs")
		}
		v.Mul(v, s.V)
		return &Scalar{V: v}, nil
	} else {
		return nil, errs.NewFailed("rhs is not a pallas scalar")
	}
}

func (s *Scalar) ApplyDiv(x algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) (curves.Scalar, error) {
	return s.Div(x.Exp(n))
}

// === Ring Methods.

func (s *Scalar) Sqrt() (curves.Scalar, error) {
	value, wasSquare := new(fq.Fq).Sqrt(s.V)
	if !wasSquare {
		return nil, errs.NewFailed("not a square")
	}
	return &Scalar{
		V: value,
	}, nil
}

func (s *Scalar) MulAdd(y algebra.PreSemiRingElement[curves.ScalarField, curves.Scalar], z algebra.PreSemiRingElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
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
	exponent, ok := s.Structure().Element().SetNat(k).Unwrap().(*Scalar)
	if !ok {
		panic("k is not a pallas scalar")
	}

	value := new(fq.Fq).Exp(s.V, exponent.V)
	return &Scalar{V: value}
}

func (s *Scalar) Neg() curves.Scalar {
	return s.AdditiveInverse()
}

func (s *Scalar) IsZero() bool {
	return s.V.IsZero()
}

func (s *Scalar) IsOne() bool {
	return s.V.IsOne()
}

func (s *Scalar) IsOdd() bool {
	return (s.V[0] & 1) == 1
}

func (s *Scalar) IsEven() bool {
	return (s.V[0] & 1) == 0
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
		gt, eq, _ := s.Nat().Cmp(r.Nat())
		return algebra.Ordering(int(gt)+int(gt)+int(eq)) - 1
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

func (s *Scalar) Max(rhs algebra.ChainElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	switch s.Cmp(rhs) {
	case algebra.Incomparable:
		panic("incomparable")
	case algebra.LessThan:
		return rhs.Unwrap()
	case algebra.Equal, algebra.GreaterThan:
		return s.Unwrap()
	default:
		panic("comparison output not supported")
	}
}

func (s *Scalar) Meet(rhs algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	return s.Min(rhs.Unwrap())
}

func (s *Scalar) Min(rhs algebra.ChainElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	switch s.Cmp(rhs) {
	case algebra.Incomparable:
		panic("incomparable")
	case algebra.LessThan, algebra.Equal:
		return s
	case algebra.GreaterThan:
		return rhs.Unwrap()
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
	return &Scalar{
		V: new(fq.Fq).SetNat(v),
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
	inputLE := bitstring.ReverseBytes(input)
	value, err := new(fq.Fq).SetBytes((*[base.FieldBytes]byte)(inputLE))
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set bytes")
	}
	return &Scalar{
		V: value,
	}, nil
}

func (*Scalar) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) > base.WideFieldBytes {
		return nil, errs.NewLength("invalid length %d > %d bytes", len(input), base.WideFieldBytes)
	}
	input = bitstring.PadToRight(bitstring.ReverseBytes(input), base.WideFieldBytes-len(input))
	return &Scalar{
		V: new(fq.Fq).SetBytesWide((*[base.WideFieldBytes]byte)(input)),
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
	S, ok := sc.(*Scalar)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.V = S.V
	return nil
}

// === Misc.

func (s *Scalar) GetFq() *fq.Fq {
	return new(fq.Fq).Set(s.V)
}

func (s *Scalar) SetFq(element *fq.Fq) *Scalar {
	s.V = element
	return s
}
func (s *Scalar) HashCode() uint64 {
	return s.Uint64()
}
