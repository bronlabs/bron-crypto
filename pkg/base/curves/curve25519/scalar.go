package curve25519

import (
	"crypto/subtle"
	"encoding"
	"encoding/binary"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	saferith_utils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

var _ curves.Scalar = (*Scalar)(nil)
var _ encoding.BinaryMarshaler = (*Scalar)(nil)
var _ encoding.BinaryUnmarshaler = (*Scalar)(nil)
var _ json.Unmarshaler = (*Scalar)(nil)

type Scalar struct {
	V [32]byte

	_ ds.Incomparable
}

func NewScalar(input uint64) *Scalar {
	s := make([]byte, 32)
	binary.LittleEndian.PutUint64(s, input)
	var scalar [32]byte
	copy(scalar[:], s)
	return &Scalar{V: scalar}
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

func (s *Scalar) Equal(rhs curves.Scalar) bool {
	r, ok := rhs.(*Scalar)
	return ok && subtle.ConstantTimeCompare(s.V[:], r.V[:]) == 1
}

func (s *Scalar) Clone() curves.Scalar {
	return &Scalar{
		V: s.V,
	}
}

// === Additive Groupoid Methods.

func (*Scalar) Add(rhs algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	panic("not implemented")
}

func (s *Scalar) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
	return s.Add(x.Unwrap().Mul(reducedN))
}

func (*Scalar) Double() curves.Scalar {
	panic("not implemented")
}

func (s *Scalar) Triple() curves.Scalar {
	return s.Double().Add(s)
}

// === Multiplicative Groupoid Methods.

func (*Scalar) Mul(rhs algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	panic("not implemented")
}

func (s *Scalar) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	return s.Mul(x.Exp(n))
}

func (*Scalar) Square() curves.Scalar {
	panic("not implemented")
}

func (*Scalar) Cube() curves.Scalar {
	panic("not implemented")
}

// === Additive Monoid Methods.

func (s *Scalar) IsAdditiveIdentity() bool {
	return s.V == [32]byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
}

// === Multiplicative Monoid Methods.

func (*Scalar) IsMultiplicativeIdentity() bool {
	panic("not implemented")
}

// === Additive Group Methods.

func (*Scalar) AdditiveInverse() curves.Scalar {
	panic("not implemented")
}

func (s *Scalar) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Add(of).IsAdditiveIdentity()
}

func (*Scalar) Sub(rhs algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	panic("not implemented")
}

func (s *Scalar) ApplySub(x algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
	return s.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (*Scalar) MultiplicativeInverse() (curves.Scalar, error) {
	panic("not implemented")
}

func (s *Scalar) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Mul(of).IsMultiplicativeIdentity()
}

func (*Scalar) Div(rhs algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	panic("not implemented")
}

func (s *Scalar) ApplyDiv(x algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) (curves.Scalar, error) {
	return s.Div(x.Exp(n))
}

// === Ring Methods.

func (*Scalar) Sqrt() (curves.Scalar, error) {
	panic("not implemented")
}

func (*Scalar) MulAdd(y algebra.RgElement[curves.ScalarField, curves.Scalar], z algebra.RgElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	panic("not implemented")
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
	v := NewScalarField().One()
	for i := new(saferith.Nat).SetUint64(0); saferith_utils.NatIsLess(i, k); i = new(saferith.Nat).Add(i, saferith_utils.NatOne, k.AnnouncedLen()) {
		v = v.Mul(s)
	}
	return v
}

func (s *Scalar) Neg() curves.Scalar {
	return s.AdditiveInverse()
}

func (s *Scalar) IsZero() bool {
	return s.IsAdditiveIdentity()
}

func (s *Scalar) IsOne() bool {
	return s.IsMultiplicativeIdentity()
}

func (*Scalar) IsOdd() bool {
	panic("not implemented")
}

func (*Scalar) IsEven() bool {
	panic("not implemented")
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

func (*Scalar) Cmp(rhs algebra.OrderTheoreticLatticeElement[curves.ScalarField, curves.Scalar]) algebra.Ordering {
	panic("not implemented")
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

func (*Scalar) SetNat(x *saferith.Nat) curves.Scalar {
	panic("not implemented")
}

func (*Scalar) Nat() *saferith.Nat {
	panic("not implemented")
}

func (s *Scalar) Bytes() []byte {
	return s.V[:]
}

func (*Scalar) SetBytesWide(input []byte) (sc curves.Scalar, err error) {
	panic("not implemented")
}

func (*Scalar) SetBytes(input []byte) (sc curves.Scalar, err error) {
	var ss [base.FieldBytes]byte
	copy(ss[:], input)
	return &Scalar{V: ss}, nil
}

func (*Scalar) SetBytesLE(bytes []byte) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
}

func (*Scalar) SetBytesWideLE(bytes []byte) (curves.Scalar, error) {
	//TODO implement me
	panic("implement me")
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
func (s *Scalar) HashCode() uint64 {
	return s.Uint64()
}
