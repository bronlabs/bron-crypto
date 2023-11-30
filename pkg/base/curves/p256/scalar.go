package p256

import (
	"bytes"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256/impl/fq"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/serialisation"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ curves.Scalar[CurveIdentifierP256] = (*ScalarP256)(nil)

type ScalarP256 struct {
	Value *impl.FieldValue

	_ types.Incomparable
}

func NewScalar() curves.Scalar[CurveIdentifierP256] {
	emptyScalar := &ScalarP256{}
	result, _ := emptyScalar.Zero().(*ScalarP256)
	return result
}

func (*ScalarP256) Curve() curves.Curve[CurveIdentifierP256] {
	return &p256Instance
}

func (*ScalarP256) CurveName() string {
	return Name
}

func (s *ScalarP256) Random(prng io.Reader) (curves.Scalar[CurveIdentifierP256], error) {
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

func (*ScalarP256) Hash(inputs ...[]byte) (curves.Scalar[CurveIdentifierP256], error) {
	u, err := New().HashToScalars(1, bytes.Join(inputs, nil), nil)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "hash to scalar failed for p256")
	}
	return u[0], nil
}

func (*ScalarP256) Zero() curves.Scalar[CurveIdentifierP256] {
	return &ScalarP256{
		Value: fq.New().SetZero(),
	}
}

func (*ScalarP256) One() curves.Scalar[CurveIdentifierP256] {
	return &ScalarP256{
		Value: fq.New().SetOne(),
	}
}

func (s *ScalarP256) IsZero() bool {
	return s.Value.IsZero() == 1
}

func (s *ScalarP256) IsOne() bool {
	return s.Value.IsOne() == 1
}

func (s *ScalarP256) IsOdd() bool {
	return s.Value.Bytes()[0]&1 == 1
}

func (s *ScalarP256) IsEven() bool {
	return s.Value.Bytes()[0]&1 == 0
}

func (*ScalarP256) New(value uint64) curves.Scalar[CurveIdentifierP256] {
	return &ScalarP256{
		Value: fq.New().SetUint64(value),
	}
}

func (s *ScalarP256) Cmp(rhs curves.Scalar[CurveIdentifierP256]) int {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*ScalarP256)
	if ok {
		return s.Value.Cmp(r.Value)
	} else {
		panic("rhs is not ScalarP256")
	}
}

func (s *ScalarP256) Square() curves.Scalar[CurveIdentifierP256] {
	return &ScalarP256{
		Value: fq.New().Square(s.Value),
	}
}

func (s *ScalarP256) Double() curves.Scalar[CurveIdentifierP256] {
	return &ScalarP256{
		Value: fq.New().Double(s.Value),
	}
}

func (s *ScalarP256) Invert() (curves.Scalar[CurveIdentifierP256], error) {
	value, wasInverted := fq.New().Invert(s.Value)
	if !wasInverted {
		return nil, errs.NewFailed("inverse doesn't exist")
	}
	return &ScalarP256{
		Value: value,
	}, nil
}

func (s *ScalarP256) Sqrt() (curves.Scalar[CurveIdentifierP256], error) {
	value, wasSquare := fq.New().Sqrt(s.Value)
	if !wasSquare {
		return nil, errs.NewFailed("not a square")
	}
	return &ScalarP256{
		Value: value,
	}, nil
}

func (s *ScalarP256) Cube() curves.Scalar[CurveIdentifierP256] {
	value := fq.New().Mul(s.Value, s.Value)
	value.Mul(value, s.Value)
	return &ScalarP256{
		Value: value,
	}
}

func (s *ScalarP256) Add(rhs curves.Scalar[CurveIdentifierP256]) curves.Scalar[CurveIdentifierP256] {
	r, ok := rhs.(*ScalarP256)
	if ok {
		return &ScalarP256{
			Value: fq.New().Add(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarP256")
	}
}

func (s *ScalarP256) Sub(rhs curves.Scalar[CurveIdentifierP256]) curves.Scalar[CurveIdentifierP256] {
	r, ok := rhs.(*ScalarP256)
	if ok {
		return &ScalarP256{
			Value: fq.New().Sub(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarP256")
	}
}

func (s *ScalarP256) Mul(rhs curves.Scalar[CurveIdentifierP256]) curves.Scalar[CurveIdentifierP256] {
	r, ok := rhs.(*ScalarP256)
	if ok {
		return &ScalarP256{
			Value: fq.New().Mul(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarP256")
	}
}

func (s *ScalarP256) MulAdd(y, z curves.Scalar[CurveIdentifierP256]) curves.Scalar[CurveIdentifierP256] {
	return s.Mul(y).Add(z)
}

func (s *ScalarP256) Div(rhs curves.Scalar[CurveIdentifierP256]) curves.Scalar[CurveIdentifierP256] {
	r, ok := rhs.(*ScalarP256)
	if ok {
		v, wasInverted := fq.New().Invert(r.Value)
		if !wasInverted {
			panic("cannot invert scalar")
		}
		v.Mul(v, s.Value)
		return &ScalarP256{Value: v}
	} else {
		panic("rhs is not ScalarP256")
	}
}

func (s *ScalarP256) Exp(k curves.Scalar[CurveIdentifierP256]) curves.Scalar[CurveIdentifierP256] {
	exponent, ok := k.(*ScalarP256)
	if !ok {
		panic("rhs is not ScalarP256")
	}

	value := fq.New().Exp(s.Value, exponent.Value)
	return &ScalarP256{Value: value}
}

func (s *ScalarP256) Neg() curves.Scalar[CurveIdentifierP256] {
	return &ScalarP256{
		Value: fq.New().Neg(s.Value),
	}
}

func (*ScalarP256) SetNat(v *saferith.Nat) (curves.Scalar[CurveIdentifierP256], error) {
	if v == nil {
		return nil, errs.NewIsNil("'v' cannot be nil")
	}
	value := fq.New().SetNat(v)
	return &ScalarP256{
		Value: value,
	}, nil
}

func (s *ScalarP256) Nat() *saferith.Nat {
	return s.Value.Nat()
}

func (s *ScalarP256) Uint64() uint64 {
	return s.Nat().Big().Uint64()
}

func (s *ScalarP256) Bytes() []byte {
	t := s.Value.Bytes()
	return bitstring.ReverseBytes(t[:])
}

func (*ScalarP256) SetBytes(input []byte) (curves.Scalar[CurveIdentifierP256], error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewInvalidLength("invalid length")
	}
	var seq [base.FieldBytes]byte
	copy(seq[:], bitstring.ReverseBytes(input))
	value, err := fq.New().SetBytes(&seq)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set bytes")
	}
	return &ScalarP256{
		Value: value,
	}, nil
}

func (*ScalarP256) SetBytesWide(input []byte) (curves.Scalar[CurveIdentifierP256], error) {
	if len(input) > base.WideFieldBytes {
		return nil, errs.NewInvalidLength("invalid length")
	}
	var seq [64]byte
	copy(seq[:], bitstring.ReverseBytes(input))
	return &ScalarP256{
		Value: fq.New().SetBytesWide(&seq),
	}, nil
}

func (s *ScalarP256) Clone() curves.Scalar[CurveIdentifierP256] {
	return &ScalarP256{
		Value: fq.New().Set(s.Value),
	}
}

func (s *ScalarP256) MarshalBinary() ([]byte, error) {
	res, err := serialisation.ScalarMarshalBinary(s.Clone())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "marshal binary failed")
	}
	return res, nil
}

func (s *ScalarP256) UnmarshalBinary(input []byte) error {
	sc, err := serialisation.ScalarUnmarshalBinary(Name, s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "unmarshal binary failed")
	}
	ss, ok := sc.(*ScalarP256)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *ScalarP256) MarshalText() ([]byte, error) {
	res, err := serialisation.ScalarMarshalText(s.Clone())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "marshal text failed")
	}
	return res, nil
}

func (s *ScalarP256) UnmarshalText(input []byte) error {
	sc, err := serialisation.ScalarUnmarshalText(Name, s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ss, ok := sc.(*ScalarP256)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	return nil
}

func (s *ScalarP256) MarshalJSON() ([]byte, error) {
	res, err := serialisation.ScalarMarshalJson(Name, s.Clone())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not marshal")
	}
	return res, nil
}

func (s *ScalarP256) UnmarshalJSON(input []byte) error {
	sc, err := serialisation.NewScalarFromJSON(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not extract a scalar from json")
	}
	S, ok := sc.(*ScalarP256)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.Value = S.Value
	return nil
}
