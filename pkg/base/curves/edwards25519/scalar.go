package edwards25519

import (
	"encoding"
	"encoding/json"
	"slices"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/bitstring"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	edwards25519Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519/impl"
	curvesImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl"
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

var _ curves.Scalar = (*Scalar)(nil)
var _ encoding.BinaryMarshaler = (*Scalar)(nil)
var _ encoding.BinaryUnmarshaler = (*Scalar)(nil)
var _ json.Unmarshaler = (*Scalar)(nil)

type Scalar struct {
	V edwards25519Impl.Fq
}

func NewScalar(input uint64) *Scalar {
	result := new(Scalar)
	result.V.SetUint64(input)
	return result
}

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

func (s *Scalar) Equal(rhs curves.Scalar) bool {
	return s.Eq(rhs) == 1
}

func (s *Scalar) Eq(rhs curves.Scalar) uint64 {
	rhse, ok := rhs.(*Scalar)
	if !ok {
		return 0
	}
	return s.V.Equals(&rhse.V)
}

func (s *Scalar) Clone() curves.Scalar {
	clone := new(Scalar)
	clone.V.Set(&s.V)
	return clone
}

// === Additive Groupoid Methods.

func (s *Scalar) Add(rhs algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if !ok {
		panic("rhs is not ScalarEd25519")
	}

	result := new(Scalar)
	result.V.Add(&s.V, &r.V)
	return result
}

func (s *Scalar) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
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
		panic("rhs is not ScalarEd25519")
	}

	result := new(Scalar)
	result.V.Mul(&s.V, &r.V)
	return result
}

func (s *Scalar) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	return s.Mul(x.Exp(n))
}

func (s *Scalar) Square() curves.Scalar {
	result := new(Scalar)
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
	result := new(Scalar)
	result.V.Neg(&s.V)
	return result
}

func (s *Scalar) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Add(of).IsAdditiveIdentity()
}

func (s *Scalar) Sub(rhs algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if !ok {
		panic("rhs is not ScalarEd25519")
	}

	result := new(Scalar)
	result.V.Sub(&s.V, &r.V)
	return result
}

func (s *Scalar) ApplySub(x algebra.AdditiveGroupElement[curves.ScalarField, curves.Scalar], n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
	return s.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (s *Scalar) MultiplicativeInverse() (curves.Scalar, error) {
	result := new(Scalar)
	ok := result.V.Inv(&s.V)
	if ok != 1 {
		return nil, errs.NewFailed("division by zero")
	}

	return result, nil
}

func (s *Scalar) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) bool {
	return s.Mul(of).IsMultiplicativeIdentity()
}

func (s *Scalar) Div(rhs algebra.MultiplicativeGroupElement[curves.ScalarField, curves.Scalar]) (curves.Scalar, error) {
	r, ok := rhs.(*Scalar)
	if !ok {
		panic("rhs is not ScalarEd25519")
	}

	result := new(Scalar)
	ok2 := result.V.Div(&s.V, &r.V)
	if ok2 != 1 {
		return nil, errs.NewFailed("division by zero")
	}

	return result, nil
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
	result := new(Scalar)
	ok := result.V.Sqrt(&s.V)
	if ok != 1 {
		return nil, errs.NewFailed("quadratic non residue")
	}

	return result, nil
}

func (*Scalar) MulAdd(y algebra.RingElement[curves.ScalarField, curves.Scalar], z algebra.RingElement[curves.ScalarField, curves.Scalar]) curves.Scalar {
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
	kBytes := k.Bytes()
	slices.Reverse(kBytes)

	result := new(Scalar)
	fieldsImpl.Pow(&result.V, &s.V, kBytes)
	return result
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
		g, e, _ := s.Nat().Cmp(r.Nat())
		return algebra.Ordering((int(g) + int(g) + int(e)) - 1)
	}

	return algebra.Incomparable
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
	if x == nil {
		return nil
	}
	v := new(saferith.Nat).Mod(x, NewScalarField().Order())
	vBytes := v.Bytes()
	slices.Reverse(vBytes)

	result := new(Scalar)
	result.V.SetBytesWide(vBytes)
	return result
}

func (s *Scalar) Nat() *saferith.Nat {
	buf := s.V.Bytes()
	slices.Reverse(buf)
	return new(saferith.Nat).SetBytes(buf)
}

func (s *Scalar) Bytes() []byte {
	t := s.V.Bytes()
	slices.Reverse(t)
	return t
}

// SetBytesCanonicalLE takes input a 32-byte long array and returns a ed25519 scalar.
// The input must be 32-byte long and must be a reduced bytes.
func (*Scalar) SetBytesCanonicalLE(input []byte) (curves.Scalar, error) {
	result := new(Scalar)
	ok := result.V.SetBytes(input)
	if ok != 1 {
		return nil, errs.NewFailed("invalid input")
	}
	return result, nil
}

// SetBytesWithClampingLE takes input a 32-byte long array, applies the buffer
// pruning described in RFC 8032, Section 5.1.5 (also known as clamping) and
// returns the resulting ed25519 scalar.
func (*Scalar) SetBytesWithClampingLE(input []byte) (curves.Scalar, error) {
	if len(input) != 32 {
		return nil, errs.NewLength("input")
	}

	var buffer [32]byte
	copy(buffer[:], input)
	buffer[0] &= 0xf8
	buffer[31] |= 0x40

	result := new(Scalar)
	ok := result.V.SetBytes(buffer[:])
	if ok != 1 {
		return nil, errs.NewFailed("invalid input")
	}

	return result, nil
}

// SetBytesWide takes input a 64-byte long byte array, reduce it and return an ed25519 scalar.
// It uses SetUniformBytes of https://pkg.go.dev/filippo.io/edwards25519
// If bytes is not of the right length, it pads it with 0s.
func (*Scalar) SetBytesWide(input []byte) (sc curves.Scalar, err error) {
	buf := bitstring.ReverseBytes(input)
	result := new(Scalar)
	ok := result.V.SetBytesWide(buf)
	if ok != 1 {
		return nil, errs.NewFailed("invalid input")
	}

	return result, nil
}

func (*Scalar) SetBytesWideLE(inputLE []byte) (sc curves.Scalar, err error) {
	result := new(Scalar)
	ok := result.V.SetBytesWide(inputLE)
	if ok != 1 {
		return nil, errs.NewFailed("invalid input")
	}

	return result, nil
}

// SetBytes takes input a 32-byte array and maps it to an ed25519 scalar:
//   - If the input is reduced (< 2^255 - 19), it performs the mapping using
//     `filipo.Scalar.SetCanonicalBytes`.
//   - If the input is not reduced (< 2^255 - 19), it treats the array as a wide
//     scalar and maps it using `filipo.Scalar.SetUniformBytes`. WARNING: This
//     generates a biased scalar. Use `Random` or `Hash` for unbiased scalars.
func (*Scalar) SetBytes(input []byte) (sc curves.Scalar, err error) {
	result := new(Scalar)
	ok := result.V.SetBytes(bitstring.ReverseBytes(input))
	if ok != 1 {
		return nil, errs.NewFailed("invalid input")
	}

	return result, nil
}

func (*Scalar) SetBytesLE(inputLE []byte) (sc curves.Scalar, err error) {
	result := new(Scalar)
	ok := result.V.SetBytes(inputLE)
	if ok != 1 {
		return nil, errs.NewFailed("invalid input")
	}

	return result, nil
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
	name, _, err := curvesImpl.ParseBinary(input)
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
	s.V.Set(&ss.V)
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
	sc, err := curvesImpl.UnmarshalJson(s.ScalarField().Name(), s.SetBytes, input)
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
