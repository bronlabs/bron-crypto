package edwards25519

import (
	"bytes"
	"io"
	"strings"

	filippo "filippo.io/edwards25519"
	"github.com/bwesterb/go-ristretto"
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var _ curves.Scalar = (*ScalarEd25519)(nil)

type ScalarEd25519 struct {
	Value *filippo.Scalar

	_ helper_types.Incomparable
}

func (*ScalarEd25519) Curve() curves.Curve {
	return &edwards25519Instance
}

func (*ScalarEd25519) CurveName() string {
	return Name
}

func (s *ScalarEd25519) Random(prng io.Reader) curves.Scalar {
	if prng == nil {
		panic("prng in nil")
	}
	var seed [64]byte
	if _, err := prng.Read(seed[:]); err != nil {
		panic(err)
	}
	return s.Hash(seed[:])
}

func (*ScalarEd25519) Hash(inputs ...[]byte) curves.Scalar {
	v := new(ristretto.Scalar).Derive(bytes.Join(inputs, nil))
	var data [32]byte
	v.BytesInto(&data)
	value, err := filippo.NewScalar().SetCanonicalBytes(data[:])
	if err != nil {
		panic("cannot set bytes")
	}
	return &ScalarEd25519{Value: value}
}

func (*ScalarEd25519) Zero() curves.Scalar {
	return &ScalarEd25519{
		Value: filippo.NewScalar(),
	}
}

func (*ScalarEd25519) One() curves.Scalar {
	return &ScalarEd25519{
		Value: filippo.NewScalar().Set(scOne),
	}
}

func (s *ScalarEd25519) IsZero() bool {
	i := byte(0)
	for _, b := range s.Value.Bytes() {
		i |= b
	}
	return i == 0
}

func (s *ScalarEd25519) IsOne() bool {
	data := s.Value.Bytes()
	i := byte(0)
	for j := 1; j < len(data); j++ {
		i |= data[j]
	}
	return i == 0 && data[0] == 1
}

func (s *ScalarEd25519) IsOdd() bool {
	return s.Value.Bytes()[0]&1 == 1
}

func (s *ScalarEd25519) IsEven() bool {
	return s.Value.Bytes()[0]&1 == 0
}

func (*ScalarEd25519) New(input uint64) curves.Scalar {
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

	return &ScalarEd25519{
		Value: value,
	}
}

func (s *ScalarEd25519) Cmp(rhs curves.Scalar) int {
	r := s.Sub(rhs)
	if r != nil && r.IsZero() {
		return 0
	} else {
		return -2
	}
}

func (s *ScalarEd25519) Square() curves.Scalar {
	value := filippo.NewScalar().Multiply(s.Value, s.Value)
	return &ScalarEd25519{Value: value}
}

func (s *ScalarEd25519) Double() curves.Scalar {
	return &ScalarEd25519{
		Value: filippo.NewScalar().Add(s.Value, s.Value),
	}
}

func (s *ScalarEd25519) Invert() (curves.Scalar, error) {
	return &ScalarEd25519{
		Value: filippo.NewScalar().Invert(s.Value),
	}, nil
}

func (s *ScalarEd25519) Sqrt() (curves.Scalar, error) {
	modulus25519, _ := new(saferith.Nat).SetHex(strings.ToUpper("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"))

	x := s.Nat()
	x = new(saferith.Nat).ModSqrt(x, saferith.ModulusFromNat(modulus25519))
	return s.SetNat(x)
}

func (s *ScalarEd25519) Cube() curves.Scalar {
	value := filippo.NewScalar().Multiply(s.Value, s.Value)
	value.Multiply(value, s.Value)
	return &ScalarEd25519{Value: value}
}

func (s *ScalarEd25519) Add(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarEd25519)
	if ok {
		return &ScalarEd25519{
			Value: filippo.NewScalar().Add(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarEd25519")
	}
}

func (s *ScalarEd25519) Sub(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarEd25519)
	if ok {
		return &ScalarEd25519{
			Value: filippo.NewScalar().Subtract(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarEd25519")
	}
}

func (s *ScalarEd25519) Mul(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarEd25519)
	if ok {
		return &ScalarEd25519{
			Value: filippo.NewScalar().Multiply(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarEd25519")
	}
}

func (s *ScalarEd25519) MulAdd(y, z curves.Scalar) curves.Scalar {
	yy, ok := y.(*ScalarEd25519)
	if !ok {
		panic("y is not ScalarEd25519")
	}
	zz, ok := z.(*ScalarEd25519)
	if !ok {
		panic("z is not ScalarEd25519")
	}
	return &ScalarEd25519{Value: filippo.NewScalar().MultiplyAdd(s.Value, yy.Value, zz.Value)}
}

func (s *ScalarEd25519) Div(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarEd25519)
	if ok {
		value := filippo.NewScalar().Invert(r.Value)
		value.Multiply(value, s.Value)
		return &ScalarEd25519{Value: value}
	} else {
		panic("rhs is not ScalarEd25519")
	}
}

func (s *ScalarEd25519) Exp(k curves.Scalar) curves.Scalar {
	exp, ok := k.(*ScalarEd25519)
	if !ok {
		panic("k is not ScalarEd25519")
	}

	v := new(ScalarEd25519).One()
	for i := new(ScalarEd25519).Zero(); i.Cmp(exp) < 0; i = i.Add(new(ScalarEd25519).One()) {
		v = v.Mul(s)
	}
	return v
}

func (s *ScalarEd25519) Neg() curves.Scalar {
	return &ScalarEd25519{
		Value: filippo.NewScalar().Negate(s.Value),
	}
}

func (*ScalarEd25519) SetNat(x *saferith.Nat) (curves.Scalar, error) {
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
	return &ScalarEd25519{Value: value}, nil
}

func (s *ScalarEd25519) Nat() *saferith.Nat {
	buf := bitstring.ReverseBytes(s.Value.Bytes())
	return new(saferith.Nat).SetBytes(buf)
}

func (s *ScalarEd25519) Bytes() []byte {
	return s.Value.Bytes()
}

// SetBytesCanonical takes input a 32-byte long array and returns a ed25519 scalar.
// The input must be 32-byte long and must be a reduced bytes.
func (*ScalarEd25519) SetBytesCanonical(input []byte) (curves.Scalar, error) {
	if len(input) != 32 {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	value, err := filippo.NewScalar().SetCanonicalBytes(input)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "set canonical bytes")
	}
	return &ScalarEd25519{Value: value}, nil
}

// SetBytesWide takes input a 64-byte long byte array, reduce it and return an ed25519 scalar.
// It uses SetUniformBytes of fillipo.io/filippo - https://github.com/FiloSottile/filippo/blob/v1.0.0-rc.1/scalar.go#L85
// If bytes is not of the right length, it returns nil and an error.
func (*ScalarEd25519) SetBytesWide(input []byte) (curves.Scalar, error) {
	value, err := filippo.NewScalar().SetUniformBytes(input)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "set uniform bytes")
	}
	return &ScalarEd25519{Value: value}, nil
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

// SetBytes takes input a 32-byte long array and returns a ed25519 scalar.
// The input must be 32-byte long.
func (*ScalarEd25519) SetBytes(input []byte) (result curves.Scalar, err error) {
	if len(input) != 32 {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	var value *filippo.Scalar
	if isReduced(input) {
		value, err = filippo.NewScalar().SetCanonicalBytes(input)
		if err != nil {
			return nil, errs.WrapSerializationError(err, "set canonical bytes")
		}
	} else {
		var wideBytes [64]byte
		copy(wideBytes[:], input[:])
		value, err = filippo.NewScalar().SetUniformBytes(wideBytes[:])
		if err != nil {
			return nil, errs.WrapSerializationError(err, "set uniform bytes")
		}
	}
	return &ScalarEd25519{Value: value}, nil
}

func (s *ScalarEd25519) Clone() curves.Scalar {
	return &ScalarEd25519{
		Value: filippo.NewScalar().Set(s.Value),
	}
}

func (s *ScalarEd25519) MarshalBinary() ([]byte, error) {
	return internal.ScalarMarshalBinary(s)
}

func (s *ScalarEd25519) UnmarshalBinary(input []byte) error {
	sc, err := internal.ScalarUnmarshalBinary(Name, s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "scalar unmarshal binary failed")
	}
	ss, ok := sc.(*ScalarEd25519)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *ScalarEd25519) MarshalText() ([]byte, error) {
	return internal.ScalarMarshalText(s)
}

func (s *ScalarEd25519) UnmarshalText(input []byte) error {
	sc, err := internal.ScalarUnmarshalText(Name, s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "scalar unmarshal binary failed")
	}
	ss, ok := sc.(*ScalarEd25519)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *ScalarEd25519) GetEdwardsScalar() *filippo.Scalar {
	return filippo.NewScalar().Set(s.Value)
}

func (*ScalarEd25519) SetEdwardsScalar(sc *filippo.Scalar) *ScalarEd25519 {
	return &ScalarEd25519{Value: filippo.NewScalar().Set(sc)}
}

func (s *ScalarEd25519) MarshalJSON() ([]byte, error) {
	return internal.ScalarMarshalJson(Name, s)
}

func (s *ScalarEd25519) UnmarshalJSON(input []byte) error {
	sc, err := internal.NewScalarFromJSON(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not extract a scalar from json")
	}
	S, ok := sc.(*ScalarEd25519)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.Value = S.Value
	return nil
}
