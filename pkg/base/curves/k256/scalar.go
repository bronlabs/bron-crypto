package k256

import (
	"bytes"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl/fq"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/serialisation"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ curves.Scalar = (*Scalar)(nil)

type Scalar struct {
	Value *impl.FieldValue

	_ types.Incomparable
}

func (*Scalar) Curve() curves.Curve {
	return &k256Instance
}

func (s *Scalar) Random(prng io.Reader) (curves.Scalar, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	var seed [base.WideFieldBytes]byte
	_, err := prng.Read(seed[:])
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not read from prng")
	}
	value, err := s.SetBytesWide(seed[:])
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set bytes")
	}
	return value, nil
}

func (*Scalar) Hash(inputs ...[]byte) (curves.Scalar, error) {
	u, err := New().HashToScalars(1, bytes.Join(inputs, nil), nil)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "hash to scalar failed for k256")
	}
	return u[0], nil
}

func (*Scalar) Zero() curves.Scalar {
	return &Scalar{
		Value: fq.New().SetZero(),
	}
}

func (*Scalar) One() curves.Scalar {
	return &Scalar{
		Value: fq.New().SetOne(),
	}
}

func (s *Scalar) IsZero() bool {
	return s.Value.IsZero() == 1
}

func (s *Scalar) IsOne() bool {
	return s.Value.IsOne() == 1
}

func (s *Scalar) IsOdd() bool {
	return s.Value.Bytes()[0]&1 == 1
}

func (s *Scalar) IsEven() bool {
	return s.Value.Bytes()[0]&1 == 0
}

func (*Scalar) New(value uint64) curves.Scalar {
	return &Scalar{
		Value: fq.New().SetUint64(value),
	}
}

func (s *Scalar) Cmp(rhs curves.Scalar) int {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Scalar)
	if ok {
		return s.Value.Cmp(r.Value)
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *Scalar) Square() curves.Scalar {
	return &Scalar{
		Value: fq.New().Square(s.Value),
	}
}

func (s *Scalar) Double() curves.Scalar {
	return &Scalar{
		Value: fq.New().Double(s.Value),
	}
}

func (s *Scalar) Invert() (curves.Scalar, error) {
	value, wasInverted := fq.New().Invert(s.Value)
	if !wasInverted {
		return nil, errs.NewFailed("inverse doesn't exist")
	}
	return &Scalar{
		Value: value,
	}, nil
}

func (s *Scalar) Sqrt() (curves.Scalar, error) {
	value, wasSquare := fq.New().Sqrt(s.Value)
	if !wasSquare {
		return nil, errs.NewFailed("not a square")
	}
	return &Scalar{
		Value: value,
	}, nil
}

func (s *Scalar) Cube() curves.Scalar {
	value := fq.New().Mul(s.Value, s.Value)
	value.Mul(value, s.Value)
	return &Scalar{
		Value: value,
	}
}

func (s *Scalar) Add(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			Value: fq.New().Add(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *Scalar) Sub(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			Value: fq.New().Sub(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *Scalar) Mul(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			Value: fq.New().Mul(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *Scalar) MulAdd(y, z curves.Scalar) curves.Scalar {
	return s.Mul(y).Add(z)
}

func (s *Scalar) Div(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		v, wasInverted := fq.New().Invert(r.Value)
		if !wasInverted {
			panic("cannot invert rhs")
		}
		v.Mul(v, s.Value)
		return &Scalar{Value: v}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *Scalar) Exp(k curves.Scalar) curves.Scalar {
	exponent, ok := k.(*Scalar)
	if !ok {
		panic("rhs is not ScalarK256")
	}

	value := fq.New().Exp(s.Value, exponent.Value)
	return &Scalar{Value: value}
}

func (s *Scalar) Neg() curves.Scalar {
	return &Scalar{
		Value: fq.New().Neg(s.Value),
	}
}

func (*Scalar) SetNat(v *saferith.Nat) (curves.Scalar, error) {
	if v == nil {
		return nil, errs.NewFailed("'v' cannot be nil")
	}
	value := fq.New().SetNat(v)
	return &Scalar{
		Value: value,
	}, nil
}

func (s *Scalar) Nat() *saferith.Nat {
	return s.Value.Nat()
}

func (s *Scalar) Uint64() uint64 {
	return s.Nat().Big().Uint64()
}

func (s *Scalar) Bytes() []byte {
	t := s.Value.Bytes()
	return bitstring.ReverseBytes(t[:])
}

func (*Scalar) SetBytes(input []byte) (curves.Scalar, error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewInvalidLength("invalid length")
	}
	input = bitstring.ReverseBytes(input)
	value, err := fq.New().SetBytes((*[base.FieldBytes]byte)(input))
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set bytes")
	}
	return &Scalar{
		Value: value,
	}, nil
}

func (*Scalar) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) > base.WideFieldBytes {
		return nil, errs.NewInvalidLength("invalid length (%d > %d bytes)", len(input), base.WideFieldBytes)
	}
	input = bitstring.ReverseAndPadBytes(input, base.WideFieldBytes-len(input))
	return &Scalar{
		Value: fq.New().SetBytesWide((*[base.WideFieldBytes]byte)(input)),
	}, nil
}

func (*Scalar) CurveName() string {
	return Name
}

func (s *Scalar) Clone() curves.Scalar {
	return &Scalar{
		Value: fq.New().Set(s.Value),
	}
}

func (s *Scalar) MarshalBinary() ([]byte, error) {
	res, err := serialisation.ScalarMarshalBinary(s)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not marshal")
	}
	return res, nil
}

func (s *Scalar) UnmarshalBinary(input []byte) error {
	sc, err := serialisation.ScalarUnmarshalBinary(Name, s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *Scalar) MarshalText() ([]byte, error) {
	res, err := serialisation.ScalarMarshalText(s)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not marshal")
	}
	return res, nil
}

func (s *Scalar) UnmarshalText(input []byte) error {
	sc, err := serialisation.ScalarUnmarshalText(Name, s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *Scalar) MarshalJSON() ([]byte, error) {
	res, err := serialisation.ScalarMarshalJson(Name, s)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not marshal")
	}
	return res, nil
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
