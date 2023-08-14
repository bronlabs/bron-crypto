package edwards25519

import (
	"bytes"
	"io"
	"math/big"

	filippo "filippo.io/edwards25519"
	"github.com/bwesterb/go-ristretto"
	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

var _ (curves.Scalar) = (*Scalar)(nil)

type Scalar struct {
	Value *filippo.Scalar
}

func (Scalar) Curve() (curves.Curve, error) {
	return edwards25519Instance, nil
}

func (Scalar) CurveName() string {
	return Name
}

func (s *Scalar) Random(prng io.Reader) curves.Scalar {
	if prng == nil {
		panic("prng in nil")
	}
	var seed [64]byte
	if _, err := prng.Read(seed[:]); err != nil {
		panic(err)
	}
	return s.Hash(seed[:])
}

func (*Scalar) Hash(inputs ...[]byte) curves.Scalar {
	v := new(ristretto.Scalar).Derive(bytes.Join(inputs, nil))
	var data [32]byte
	v.BytesInto(&data)
	value, err := filippo.NewScalar().SetCanonicalBytes(data[:])
	if err != nil {
		panic("cannot set bytes")
	}
	return &Scalar{value}
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

func (*Scalar) New(input int) curves.Scalar {
	var data [64]byte
	i := input
	if input < 0 {
		i = -input
	}
	data[0] = byte(i)
	data[1] = byte(i >> 8)
	data[2] = byte(i >> 16)
	data[3] = byte(i >> 24)
	value, err := filippo.NewScalar().SetUniformBytes(data[:])
	if err != nil {
		panic("cannot set bytes")
	}
	if input < 0 {
		value.Negate(value)
	}

	return &Scalar{
		value,
	}
}

func (s *Scalar) Cmp(rhs curves.Scalar) int {
	r := s.Sub(rhs)
	if r != nil && r.IsZero() {
		return 0
	} else {
		return -2
	}
}

func (s *Scalar) Square() curves.Scalar {
	value := filippo.NewScalar().Multiply(s.Value, s.Value)
	return &Scalar{value}
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
	bi25519, _ := new(big.Int).SetString("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED", 16)
	x := s.BigInt()
	x.ModSqrt(x, bi25519)
	return s.SetBigInt(x)
}

func (s *Scalar) Cube() curves.Scalar {
	value := filippo.NewScalar().Multiply(s.Value, s.Value)
	value.Multiply(value, s.Value)
	return &Scalar{value}
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
		return &Scalar{value}
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

func (*Scalar) SetBigInt(x *big.Int) (curves.Scalar, error) {
	if x == nil {
		return nil, errs.NewDeserializationFailed("invalid value")
	}

	bi25519, _ := new(big.Int).SetString("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED", 16)
	var v big.Int
	buf := v.Mod(x, bi25519).Bytes()
	var rBuf [32]byte
	for i := 0; i < len(buf) && i < 32; i++ {
		rBuf[i] = buf[len(buf)-i-1]
	}
	value, err := filippo.NewScalar().SetCanonicalBytes(rBuf[:])
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "set canonical bytes failed")
	}
	return &Scalar{value}, nil
}

func (s *Scalar) BigInt() *big.Int {
	var ret big.Int
	buf := bitstring.ReverseBytes(s.Value.Bytes())
	return ret.SetBytes(buf)
}

func (s *Scalar) Bytes() []byte {
	return s.Value.Bytes()
}

// SetBytesCanonical takes input a 32-byte long array and returns a ed25519 scalar.
// The input must be 32-byte long and must be a reduced bytes.
func (*Scalar) SetBytesCanonical(input []byte) (curves.Scalar, error) {
	if len(input) != 32 {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	value, err := filippo.NewScalar().SetCanonicalBytes(input)
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "set canonical bytes")
	}
	return &Scalar{value}, nil
}

// SetBytesWide takes input a 64-byte long byte array, reduce it and return an ed25519 scalar.
// It uses SetUniformBytes of fillipo.io/filippo - https://github.com/FiloSottile/filippo/blob/v1.0.0-rc.1/scalar.go#L85
// If bytes is not of the right length, it returns nil and an error.
func (*Scalar) SetBytesWide(input []byte) (curves.Scalar, error) {
	value, err := filippo.NewScalar().SetUniformBytes(input)
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "set uniform bytes")
	}
	return &Scalar{value}, nil
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
func (*Scalar) SetBytes(input []byte) (result curves.Scalar, err error) {
	if len(input) != 32 {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	var value *filippo.Scalar
	if isReduced(input) {
		value, err = filippo.NewScalar().SetCanonicalBytes(input)
		if err != nil {
			return nil, errs.WrapDeserializationFailed(err, "set canonical bytes")
		}
	} else {
		var wideBytes [64]byte
		copy(wideBytes[:], input[:])
		value, err = filippo.NewScalar().SetUniformBytes(wideBytes[:])
		if err != nil {
			return nil, errs.WrapDeserializationFailed(err, "set uniform bytes")
		}
	}
	return &Scalar{value}, nil
}

func (s *Scalar) Clone() curves.Scalar {
	return &Scalar{
		Value: filippo.NewScalar().Set(s.Value),
	}
}

func (s *Scalar) MarshalBinary() ([]byte, error) {
	return internal.ScalarMarshalBinary(s)
}

func (s *Scalar) UnmarshalBinary(input []byte) error {
	sc, err := internal.ScalarUnmarshalBinary(Name, s.SetBytes, input)
	if err != nil {
		return errs.WrapDeserializationFailed(err, "scalar unmarshal binary failed")
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *Scalar) MarshalText() ([]byte, error) {
	return internal.ScalarMarshalText(s)
}

func (s *Scalar) UnmarshalText(input []byte) error {
	sc, err := internal.ScalarUnmarshalText(Name, s.SetBytes, input)
	if err != nil {
		return errs.WrapDeserializationFailed(err, "scalar unmarshal binary failed")
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
	return internal.ScalarMarshalJson(Name, s)
}

func (s *Scalar) UnmarshalJSON(input []byte) error {
	sc, err := internal.NewScalarFromJSON(s.SetBytes, input)
	if err != nil {
		return errs.WrapDeserializationFailed(err, "could not extract a scalar from json")
	}
	S, ok := sc.(*Scalar)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.Value = S.Value
	return nil
}
