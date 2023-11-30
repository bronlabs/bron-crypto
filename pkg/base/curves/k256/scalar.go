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

var _ curves.Scalar[CurveIdentifierK256] = (*ScalarK256)(nil)

type ScalarK256 struct {
	Value *impl.FieldValue

	_ types.Incomparable
}

func NewScalar() *ScalarK256 {
	emptyScalar := &ScalarK256{}
	result, _ := emptyScalar.Zero().(*ScalarK256)
	return result
}

func (*ScalarK256) Curve() curves.Curve[CurveIdentifierK256] {
	return &k256Instance
}

func (s *ScalarK256) Random(prng io.Reader) (curves.Scalar[CurveIdentifierK256], error) {
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

func (*ScalarK256) Hash(inputs ...[]byte) (curves.Scalar[CurveIdentifierK256], error) {
	u, err := New().HashToScalars(1, bytes.Join(inputs, nil), nil)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "hash to scalar failed for k256")
	}
	return u[0], nil
}

func (*ScalarK256) Zero() curves.Scalar[CurveIdentifierK256] {
	return &ScalarK256{
		Value: fq.New().SetZero(),
	}
}

func (*ScalarK256) One() curves.Scalar[CurveIdentifierK256] {
	return &ScalarK256{
		Value: fq.New().SetOne(),
	}
}

func (s *ScalarK256) IsZero() bool {
	return s.Value.IsZero() == 1
}

func (s *ScalarK256) IsOne() bool {
	return s.Value.IsOne() == 1
}

func (s *ScalarK256) IsOdd() bool {
	return s.Value.Bytes()[0]&1 == 1
}

func (s *ScalarK256) IsEven() bool {
	return s.Value.Bytes()[0]&1 == 0
}

func (*ScalarK256) New(value uint64) curves.Scalar[CurveIdentifierK256] {
	return &ScalarK256{
		Value: fq.New().SetUint64(value),
	}
}

func (s *ScalarK256) Cmp(rhs curves.Scalar[CurveIdentifierK256]) int {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*ScalarK256)
	if ok {
		return s.Value.Cmp(r.Value)
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *ScalarK256) Square() curves.Scalar[CurveIdentifierK256] {
	return &ScalarK256{
		Value: fq.New().Square(s.Value),
	}
}

func (s *ScalarK256) Double() curves.Scalar[CurveIdentifierK256] {
	return &ScalarK256{
		Value: fq.New().Double(s.Value),
	}
}

func (s *ScalarK256) Invert() (curves.Scalar[CurveIdentifierK256], error) {
	value, wasInverted := fq.New().Invert(s.Value)
	if !wasInverted {
		return nil, errs.NewFailed("inverse doesn't exist")
	}
	return &ScalarK256{
		Value: value,
	}, nil
}

func (s *ScalarK256) Sqrt() (curves.Scalar[CurveIdentifierK256], error) {
	value, wasSquare := fq.New().Sqrt(s.Value)
	if !wasSquare {
		return nil, errs.NewFailed("not a square")
	}
	return &ScalarK256{
		Value: value,
	}, nil
}

func (s *ScalarK256) Cube() curves.Scalar[CurveIdentifierK256] {
	value := fq.New().Mul(s.Value, s.Value)
	value.Mul(value, s.Value)
	return &ScalarK256{
		Value: value,
	}
}

func (s *ScalarK256) Add(rhs curves.Scalar[CurveIdentifierK256]) curves.Scalar[CurveIdentifierK256] {
	r, ok := rhs.(*ScalarK256)
	if ok {
		return &ScalarK256{
			Value: fq.New().Add(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *ScalarK256) Sub(rhs curves.Scalar[CurveIdentifierK256]) curves.Scalar[CurveIdentifierK256] {
	r, ok := rhs.(*ScalarK256)
	if ok {
		return &ScalarK256{
			Value: fq.New().Sub(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *ScalarK256) Mul(rhs curves.Scalar[CurveIdentifierK256]) curves.Scalar[CurveIdentifierK256] {
	r, ok := rhs.(*ScalarK256)
	if ok {
		return &ScalarK256{
			Value: fq.New().Mul(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *ScalarK256) MulAdd(y, z curves.Scalar[CurveIdentifierK256]) curves.Scalar[CurveIdentifierK256] {
	return s.Mul(y).Add(z)
}

func (s *ScalarK256) Div(rhs curves.Scalar[CurveIdentifierK256]) curves.Scalar[CurveIdentifierK256] {
	r, ok := rhs.(*ScalarK256)
	if ok {
		v, wasInverted := fq.New().Invert(r.Value)
		if !wasInverted {
			panic("cannot invert rhs")
		}
		v.Mul(v, s.Value)
		return &ScalarK256{Value: v}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *ScalarK256) Exp(k curves.Scalar[CurveIdentifierK256]) curves.Scalar[CurveIdentifierK256] {
	exponent, ok := k.(*ScalarK256)
	if !ok {
		panic("rhs is not ScalarK256")
	}

	value := fq.New().Exp(s.Value, exponent.Value)
	return &ScalarK256{Value: value}
}

func (s *ScalarK256) Neg() curves.Scalar[CurveIdentifierK256] {
	return &ScalarK256{
		Value: fq.New().Neg(s.Value),
	}
}

func (*ScalarK256) SetNat(v *saferith.Nat) (curves.Scalar[CurveIdentifierK256], error) {
	if v == nil {
		return nil, errs.NewFailed("'v' cannot be nil")
	}
	value := fq.New().SetNat(v)
	return &ScalarK256{
		Value: value,
	}, nil
}

func (s *ScalarK256) Nat() *saferith.Nat {
	return s.Value.Nat()
}

func (s *ScalarK256) Uint64() uint64 {
	return s.Nat().Big().Uint64()
}

func (s *ScalarK256) Bytes() []byte {
	t := s.Value.Bytes()
	return bitstring.ReverseBytes(t[:])
}

func (*ScalarK256) SetBytes(input []byte) (curves.Scalar[CurveIdentifierK256], error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewInvalidLength("invalid length")
	}
	input = bitstring.ReverseBytes(input)
	value, err := fq.New().SetBytes((*[base.FieldBytes]byte)(input))
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set bytes")
	}
	return &ScalarK256{
		Value: value,
	}, nil
}

func (*ScalarK256) SetBytesWide(input []byte) (curves.Scalar[CurveIdentifierK256], error) {
	if len(input) > base.WideFieldBytes {
		return nil, errs.NewInvalidLength("invalid length (%d > %d bytes)", len(input), base.WideFieldBytes)
	}
	input = bitstring.ReverseAndPadBytes(input, base.WideFieldBytes-len(input))
	return &ScalarK256{
		Value: fq.New().SetBytesWide((*[base.WideFieldBytes]byte)(input)),
	}, nil
}

func (*ScalarK256) CurveName() string {
	return Name
}

func (s *ScalarK256) Clone() curves.Scalar[CurveIdentifierK256] {
	return &ScalarK256{
		Value: fq.New().Set(s.Value),
	}
}

func (s *ScalarK256) MarshalBinary() ([]byte, error) {
	res, err := serialisation.ScalarMarshalBinary(s.Clone())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not marshal")
	}
	return res, nil
}

func (s *ScalarK256) UnmarshalBinary(input []byte) error {
	sc, err := serialisation.ScalarUnmarshalBinary(Name, s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ss, ok := sc.(*ScalarK256)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *ScalarK256) MarshalText() ([]byte, error) {
	res, err := serialisation.ScalarMarshalText(s.Clone())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not marshal")
	}
	return res, nil
}

func (s *ScalarK256) UnmarshalText(input []byte) error {
	sc, err := serialisation.ScalarUnmarshalText(Name, s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ss, ok := sc.(*ScalarK256)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *ScalarK256) MarshalJSON() ([]byte, error) {
	res, err := serialisation.ScalarMarshalJson(Name, s.Clone())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not marshal")
	}
	return res, nil
}

func (s *ScalarK256) UnmarshalJSON(input []byte) error {
	sc, err := serialisation.NewScalarFromJSON(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not extract a scalar from json")
	}
	S, ok := sc.(*ScalarK256)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.Value = S.Value
	return nil
}
