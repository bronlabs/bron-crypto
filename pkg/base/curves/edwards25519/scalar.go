package edwards25519

import (
	"encoding"
	"encoding/json"
	"strings"

	filippo "filippo.io/edwards25519"
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

var _ curves.Scalar = (*Scalar)(nil)
var _ encoding.BinaryMarshaler = (*Scalar)(nil)
var _ encoding.BinaryUnmarshaler = (*Scalar)(nil)
var _ json.Unmarshaler = (*Scalar)(nil)

type Scalar struct {
	V *filippo.Scalar

	_ types.Incomparable
}

func NewScalar(input uint64) *Scalar {
	var data [64]byte

	data[0] = byte(input)
	data[1] = byte(input >> 8)
	data[2] = byte(input >> 16)
	data[3] = byte(input >> 24)
	data[4] = byte(input >> 32)
	data[5] = byte(input >> 40)
	data[6] = byte(input >> 48)
	data[7] = byte(input >> 52)
	value, err := filippo.NewScalar().SetUniformBytes(data[:])
	if err != nil {
		panic("cannot set bytes")
	}

	return &Scalar{
		V: value,
	}
}

// === Basic Methods.

func (s *Scalar) Equal(rhs curves.Scalar) bool {
	return s.Cmp(rhs) == 0
}

func (s *Scalar) Clone() curves.Scalar {
	return &Scalar{
		V: filippo.NewScalar().Set(s.V),
	}
}

// === Additive Groupoid Methods.

func (s *Scalar) Add(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			V: filippo.NewScalar().Add(s.V, r.V),
		}
	} else {
		panic("rhs is not ScalarEd25519")
	}
}

func (s *Scalar) ApplyAdd(x curves.Scalar, n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
	return s.Add(x.Mul(reducedN))
}

func (s *Scalar) Double() curves.Scalar {
	return &Scalar{
		V: filippo.NewScalar().Add(s.V, s.V),
	}
}

func (s *Scalar) Triple() curves.Scalar {
	return s.Double().Add(s)
}

// === Multiplicative Groupoid Methods.

func (s *Scalar) Mul(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			V: filippo.NewScalar().Multiply(s.V, r.V),
		}
	} else {
		panic("rhs is not ScalarEd25519")
	}
}

func (s *Scalar) ApplyMul(x curves.Scalar, n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
	return s.Mul(x.Exp(reducedN))
}

func (s *Scalar) Square() curves.Scalar {
	value := filippo.NewScalar().Multiply(s.V, s.V)
	return &Scalar{V: value}
}

func (s *Scalar) Cube() curves.Scalar {
	value := filippo.NewScalar().Multiply(s.V, s.V)
	value.Multiply(value, s.V)
	return &Scalar{V: value}
}

// === Additive Monoid Methods.

func (s *Scalar) IsAdditiveIdentity() bool {
	i := byte(0)
	for _, b := range s.V.Bytes() {
		i |= b
	}
	return i == 0
}

// === Multiplicative Monoid Methods.

func (s *Scalar) IsMultiplicativeIdentity() bool {
	data := s.V.Bytes()
	i := byte(0)
	for j := 1; j < len(data); j++ {
		i |= data[j]
	}
	return i == 0 && data[0] == 1
}

// === Additive Group Methods.

func (s *Scalar) AdditiveInverse() curves.Scalar {
	return &Scalar{
		V: filippo.NewScalar().Negate(s.V),
	}
}

func (s *Scalar) IsAdditiveInverse(of curves.Scalar) bool {
	return s.Add(of).IsAdditiveIdentity()
}

func (s *Scalar) Sub(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			V: filippo.NewScalar().Subtract(s.V, r.V),
		}
	} else {
		panic("rhs is not ScalarEd25519")
	}
}

func (s *Scalar) ApplySub(x curves.Scalar, n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
	return s.Sub(x.Mul(reducedN))
}

// === Multiplicative Group Methods.

func (s *Scalar) MultiplicativeInverse() curves.Scalar {
	return &Scalar{
		V: filippo.NewScalar().Invert(s.V),
	}
}

func (s *Scalar) IsMultiplicativeInverse(of curves.Scalar) bool {
	return s.Mul(of).IsMultiplicativeIdentity()
}

func (s *Scalar) Div(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		value := filippo.NewScalar().Invert(r.V)
		value.Multiply(value, s.V)
		return &Scalar{V: value}
	} else {
		panic("rhs is not ScalarEd25519")
	}
}

func (s *Scalar) ApplyDiv(x curves.Scalar, n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
	return s.Div(x.Exp(reducedN))
}

// === Ring Methods.

func (s *Scalar) Sqrt() (curves.Scalar, error) {
	modulus25519, _ := new(saferith.Nat).SetHex(strings.ToUpper("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"))

	x := s.Nat()
	x = new(saferith.Nat).ModSqrt(x, saferith.ModulusFromNat(modulus25519))
	return s.SetNat(x), nil
}

func (s *Scalar) MulAdd(y, z curves.Scalar) curves.Scalar {
	yy, ok := y.(*Scalar)
	if !ok {
		panic("y is not ScalarEd25519")
	}
	zz, ok := z.(*Scalar)
	if !ok {
		panic("z is not ScalarEd25519")
	}
	return &Scalar{V: filippo.NewScalar().MultiplyAdd(s.V, yy.V, zz.V)}
}

// === Finite Field Methods.

func (s *Scalar) SubFieldElement(index uint) curves.Scalar {
	return s
}

func (s *Scalar) Norm() curves.Scalar {
	return s
}

// === Zp Methods.

func (s *Scalar) Exp(k curves.Scalar) curves.Scalar {
	exp, ok := k.(*Scalar)
	if !ok {
		panic("k is not ScalarEd25519")
	}

	v := NewScalarField().One()
	for i := NewScalarField().Zero(); i.Cmp(exp) < 0; i = i.Add(NewScalarField().One()) {
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

func (s *Scalar) IsOdd() bool {
	return s.V.Bytes()[0]&1 == 1
}

func (s *Scalar) IsEven() bool {
	return s.V.Bytes()[0]&1 == 0
}

func (s *Scalar) Increment() {
	ee, ok := s.Add(s.ScalarField().One()).(*Scalar)
	if !ok {
		panic("invalid type")
	}
	s.V = ee.V
}

func (s *Scalar) Decrement() {
	ee, ok := s.Sub(s.ScalarField().One()).(*Scalar)
	if !ok {
		panic("invalid type")
	}
	s.V = ee.V
}

// === Ordering Methods.

func (s *Scalar) Cmp(rhs curves.Scalar) algebra.Ordering {
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

func (s *Scalar) Join(rhs curves.Scalar) curves.Scalar {
	return s.Max(rhs)
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

func (s *Scalar) Meet(rhs curves.Scalar) curves.Scalar {
	return s.Min(rhs)
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
	value, err := filippo.NewScalar().SetCanonicalBytes(utils.SlicePadRight(utils.SliceReverse(v.Bytes()), base.FieldBytes-len(v.Bytes())))
	if err != nil {
		panic(errs.WrapSerialisation(err, "set canonical bytes failed"))
	}
	return &Scalar{V: value}
}

func (s *Scalar) Nat() *saferith.Nat {
	buf := utils.SliceReverse(s.V.Bytes())
	return new(saferith.Nat).SetBytes(buf)
}

func (s *Scalar) Bytes() []byte {
	t := s.V.Bytes()
	return utils.SliceReverse(t)
}

// SetBytesCanonicalLE takes input a 32-byte long array and returns a ed25519 scalar.
// The input must be 32-byte long and must be a reduced bytes.
func (*Scalar) SetBytesCanonicalLE(input []byte) (curves.Scalar, error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	value, err := filippo.NewScalar().SetCanonicalBytes(input)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "set canonical bytes")
	}
	return &Scalar{V: value}, nil
}

// SetBytesWithClampingLE takes input a 32-byte long array, applies the buffer
// pruning described in RFC 8032, Section 5.1.5 (also known as clamping) and
// returns the resulting ed25519 scalar.
func (*Scalar) SetBytesWithClampingLE(input []byte) (curves.Scalar, error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	value, err := filippo.NewScalar().SetBytesWithClamping(input)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "set canonical bytes")
	}
	return &Scalar{V: value}, nil
}

// SetBytesWide takes input a 64-byte long byte array, reduce it and return an ed25519 scalar.
// It uses SetUniformBytes of https://pkg.go.dev/filippo.io/edwards25519
// If bytes is not of the right length, it pads it with 0s.
func (*Scalar) SetBytesWide(input []byte) (sc curves.Scalar, err error) {
	var value *filippo.Scalar
	if len(input) > base.WideFieldBytes {
		return nil, errs.NewInvalidLength("invalid input length (%d > %d)", len(input), base.WideFieldBytes)
	}
	inputLE := utils.SlicePadRight(utils.SliceReverse(input), base.WideFieldBytes-len(input))
	value, err = filippo.NewScalar().SetUniformBytes(inputLE)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "set uniform bytes")
	}
	return &Scalar{V: value}, nil
}

func isReducedLE(bytes_ []byte) bool {
	if len(bytes_) != 32 {
		return false
	}

	for i := 32 - 1; i >= 0; i-- {
		switch {
		case bytes_[i] > scMinusOne[i]:
			return false
		case bytes_[i] < scMinusOne[i]:
			return true
		}
	}
	return true
}

// SetBytes takes input a 32-byte array and maps it to an ed25519 scalar:
//   - If the input is reduced (< 2^255 - 19), it performs the mapping using
//     `filipo.Scalar.SetCanonicalBytes`.
//   - If the input is not reduced (< 2^255 - 19), it treats the array as a wide
//     scalar and maps it using `filipo.Scalar.SetUniformBytes`. WARNING: This
//     generates a biased scalar. Use `Random` or `Hash` for unbiased scalars.
func (s *Scalar) SetBytes(input []byte) (sc curves.Scalar, err error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewInvalidLength("invalid length (%d != %d)", len(input), base.FieldBytes)
	}
	inputLE := utils.SliceReverse(input)
	var value *filippo.Scalar
	if isReducedLE(inputLE) {
		value, err = filippo.NewScalar().SetCanonicalBytes(inputLE)
		if err != nil {
			return nil, errs.WrapSerialisation(err, "set canonical bytes")
		}
		return &Scalar{V: value}, nil
	} else {
		sc, err = s.SetBytesWide(inputLE)
		if err != nil {
			return nil, errs.WrapSerialisation(err, "set uniform bytes")
		}
		return sc, nil
	}
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
	if name != s.ScalarField().Curve().Name() {
		return errs.NewInvalidType("name %s is not supported", name)
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewInvalidType("invalid base field element")
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
	if name != s.ScalarField().Curve().Name() {
		return errs.NewInvalidType("name %s is not supported", name)
	}
	S, ok := sc.(*Scalar)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.V = S.V
	return nil
}

func (s *Scalar) GetEdwardsScalar() *filippo.Scalar {
	return filippo.NewScalar().Set(s.V)
}

func (*Scalar) SetEdwardsScalar(sc *filippo.Scalar) *Scalar {
	return &Scalar{V: filippo.NewScalar().Set(sc)}
}
