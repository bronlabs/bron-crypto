package edwards25519

import (
	"bytes"
	"io"
	"strings"

	filippo "filippo.io/edwards25519"
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/serialisation"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ curves.Scalar = (*Scalar)(nil)

type Scalar struct {
	Value *filippo.Scalar

	_ types.Incomparable
}

func (*Scalar) Curve() curves.Curve {
	return &edwards25519Instance
}

func (*Scalar) CurveName() string {
	return Name
}

func (s *Scalar) Random(prng io.Reader) (curves.Scalar, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	var buffer [base.WideFieldBytes]byte
	if _, err := prng.Read(buffer[:]); err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not read from prng")
	}
	res, err := s.SetBytesWide(buffer[:])
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not set bytes wide")
	}
	return res, nil
}

func (*Scalar) Hash(inputs ...[]byte) (curves.Scalar, error) {
	u, err := New().HashToScalars(1, bytes.Join(inputs, nil), nil)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "could not hash to field element in edwards25519")
	}
	return u[0], nil
}

func (*Scalar) Zero() curves.Scalar {
	return &Scalar{
		Value: filippo.NewScalar(),
	}
}

func (*Scalar) One() curves.Scalar {
	return &Scalar{
		Value: filippo.NewScalar().Set(scOne),
	}
}

func (s *Scalar) IsZero() bool {
	i := byte(0)
	for _, b := range s.Value.Bytes() {
		i |= b
	}
	return i == 0
}

func (s *Scalar) IsOne() bool {
	data := s.Value.Bytes()
	i := byte(0)
	for j := 1; j < len(data); j++ {
		i |= data[j]
	}
	return i == 0 && data[0] == 1
}

func (s *Scalar) IsOdd() bool {
	return s.Value.Bytes()[0]&1 == 1
}

func (s *Scalar) IsEven() bool {
	return s.Value.Bytes()[0]&1 == 0
}

func (*Scalar) New(input uint64) curves.Scalar {
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
		Value: value,
	}
}

func (s *Scalar) Cmp(rhs curves.Scalar) int {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Scalar)
	if ok {
		g, e, _ := s.Nat().Cmp(r.Nat())
		return (int(g) + int(g) + int(e)) - 1
	}

	return -2
}

func (s *Scalar) Square() curves.Scalar {
	value := filippo.NewScalar().Multiply(s.Value, s.Value)
	return &Scalar{Value: value}
}

func (s *Scalar) Double() curves.Scalar {
	return &Scalar{
		Value: filippo.NewScalar().Add(s.Value, s.Value),
	}
}

func (s *Scalar) Invert() (curves.Scalar, error) {
	return &Scalar{
		Value: filippo.NewScalar().Invert(s.Value),
	}, nil
}

func (s *Scalar) Sqrt() (curves.Scalar, error) {
	modulus25519, _ := new(saferith.Nat).SetHex(strings.ToUpper("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"))

	x := s.Nat()
	x = new(saferith.Nat).ModSqrt(x, saferith.ModulusFromNat(modulus25519))
	return s.SetNat(x)
}

func (s *Scalar) Cube() curves.Scalar {
	value := filippo.NewScalar().Multiply(s.Value, s.Value)
	value.Multiply(value, s.Value)
	return &Scalar{Value: value}
}

func (s *Scalar) Add(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			Value: filippo.NewScalar().Add(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarEd25519")
	}
}

func (s *Scalar) Sub(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			Value: filippo.NewScalar().Subtract(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarEd25519")
	}
}

func (s *Scalar) Mul(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			Value: filippo.NewScalar().Multiply(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarEd25519")
	}
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
	return &Scalar{Value: filippo.NewScalar().MultiplyAdd(s.Value, yy.Value, zz.Value)}
}

func (s *Scalar) Div(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		value := filippo.NewScalar().Invert(r.Value)
		value.Multiply(value, s.Value)
		return &Scalar{Value: value}
	} else {
		panic("rhs is not ScalarEd25519")
	}
}

func (s *Scalar) Exp(k curves.Scalar) curves.Scalar {
	exp, ok := k.(*Scalar)
	if !ok {
		panic("k is not ScalarEd25519")
	}

	v := new(Scalar).One()
	for i := new(Scalar).Zero(); i.Cmp(exp) < 0; i = i.Add(new(Scalar).One()) {
		v = v.Mul(s)
	}
	return v
}

func (s *Scalar) Neg() curves.Scalar {
	return &Scalar{
		Value: filippo.NewScalar().Negate(s.Value),
	}
}

func (*Scalar) SetNat(x *saferith.Nat) (curves.Scalar, error) {
	if x == nil {
		return nil, errs.NewSerializationError("invalid value")
	}

	modulus25519, _ := new(saferith.Nat).SetHex(strings.ToUpper("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"))
	v := new(saferith.Nat).Mod(x, saferith.ModulusFromNat(modulus25519))
	buf := v.Bytes()
	var rBuf [32]byte
	for i := 0; i < len(buf) && i < 32; i++ {
		rBuf[i] = buf[len(buf)-i-1]
	}
	value, err := filippo.NewScalar().SetCanonicalBytes(rBuf[:])
	if err != nil {
		return nil, errs.WrapSerializationError(err, "set canonical bytes failed")
	}
	return &Scalar{Value: value}, nil
}

func (s *Scalar) Nat() *saferith.Nat {
	buf := bitstring.ReverseBytes(s.Value.Bytes())
	return new(saferith.Nat).SetBytes(buf)
}

func (s *Scalar) Uint64() uint64 {
	return s.Nat().Big().Uint64()
}

func (s *Scalar) Bytes() []byte {
	return s.Value.Bytes()
}

// SetBytesCanonical takes input a 32-byte long array and returns a ed25519 scalar.
// The input must be 32-byte long and must be a reduced bytes.
func (*Scalar) SetBytesCanonical(input []byte) (curves.Scalar, error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	value, err := filippo.NewScalar().SetCanonicalBytes(input)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "set canonical bytes")
	}
	return &Scalar{Value: value}, nil
}

// SetBytesWide takes input a 64-byte long byte array, reduce it and return an ed25519 scalar.
// It uses SetUniformBytes of https://pkg.go.dev/filippo.io/edwards25519
// If bytes is not of the right length, it pads it with 0s.
func (*Scalar) SetBytesWide(input []byte) (sc curves.Scalar, err error) {
	var value *filippo.Scalar
	if len(input) > base.WideFieldBytes {
		return nil, errs.NewInvalidLength("invalid input length (%d > %d)", len(input), base.WideFieldBytes)
	}
	if len(input) < base.WideFieldBytes {
		input = bitstring.ReverseAndPadBytes(input, base.WideFieldBytes-len(input))
	}
	value, err = filippo.NewScalar().SetUniformBytes(input)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "set uniform bytes")
	}
	return &Scalar{Value: value}, nil
}

func isReduced(bytes_ []byte) bool {
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
	var value *filippo.Scalar
	if isReduced(input) {
		value, err = filippo.NewScalar().SetCanonicalBytes(input)
		if err != nil {
			return nil, errs.WrapSerializationError(err, "set canonical bytes")
		}
		return &Scalar{Value: value}, nil
	} else {
		sc, err = s.SetBytesWide(input)
		if err != nil {
			return nil, errs.WrapSerializationError(err, "set uniform bytes")
		}
		return sc, nil
	}
}

func (s *Scalar) Clone() curves.Scalar {
	return &Scalar{
		Value: filippo.NewScalar().Set(s.Value),
	}
}

func (s *Scalar) MarshalBinary() ([]byte, error) {
	buf, err := serialisation.ScalarMarshalBinary(s)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "scalar marshal binary failed")
	}
	return buf, nil
}

func (s *Scalar) UnmarshalBinary(input []byte) error {
	sc, err := serialisation.ScalarUnmarshalBinary(Name, s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "scalar unmarshal binary failed")
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *Scalar) MarshalText() ([]byte, error) {
	buf, err := serialisation.ScalarMarshalText(s)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "scalar marshal binary failed")
	}
	return buf, nil
}

func (s *Scalar) UnmarshalText(input []byte) error {
	sc, err := serialisation.ScalarUnmarshalText(Name, s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "scalar unmarshal binary failed")
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *Scalar) GetEdwardsScalar() *filippo.Scalar {
	return filippo.NewScalar().Set(s.Value)
}

func (*Scalar) SetEdwardsScalar(sc *filippo.Scalar) *Scalar {
	return &Scalar{Value: filippo.NewScalar().Set(sc)}
}

func (s *Scalar) MarshalJSON() ([]byte, error) {
	buf, err := serialisation.ScalarMarshalJson(Name, s)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "scalar marshal binary failed")
	}
	return buf, nil
}

func (s *Scalar) UnmarshalJSON(input []byte) error {
	sc, err := serialisation.NewScalarFromJSON(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not extract a scalar from json")
	}
	S, ok := sc.(*Scalar)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.Value = S.Value
	return nil
}
