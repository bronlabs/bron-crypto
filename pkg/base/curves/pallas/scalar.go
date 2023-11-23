package pallas

import (
	"bytes"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas/impl/fq"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/serialisation"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ curves.Scalar = (*Scalar)(nil)

type Scalar struct {
	Value *fq.Fq

	_ types.Incomparable
}

func NewScalar() *Scalar {
	emptyScalar := &Scalar{}
	result, _ := emptyScalar.Zero().(*Scalar)
	return result
}

func (*Scalar) Curve() curves.Curve {
	return &pallasInstance
}

func (*Scalar) CurveName() string {
	return Name
}

func (s *Scalar) Random(reader io.Reader) (curves.Scalar, error) {
	if reader == nil {
		return nil, errs.NewIsNil("reader is nil")
	}
	var seed [base.WideFieldBytes]byte
	_, err := reader.Read(seed[:])
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not read from reader")
	}
	value, err := s.SetBytesWide(seed[:])
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not set bytes")
	}
	return value, nil
}

func (*Scalar) Hash(inputs ...[]byte) (curves.Scalar, error) {
	u, err := New().HashToScalars(1, bytes.Join(inputs, nil), nil)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "hash to scalar failed for pallas")
	}
	return u[0], nil
}

func (*Scalar) Zero() curves.Scalar {
	return &Scalar{
		Value: new(fq.Fq).SetZero(),
	}
}

func (*Scalar) One() curves.Scalar {
	return &Scalar{
		Value: new(fq.Fq).SetOne(),
	}
}

func (s *Scalar) IsZero() bool {
	return s.Value.IsZero()
}

func (s *Scalar) IsOne() bool {
	return s.Value.IsOne()
}

func (s *Scalar) IsOdd() bool {
	return (s.Value[0] & 1) == 1
}

func (s *Scalar) IsEven() bool {
	return (s.Value[0] & 1) == 0
}

func (*Scalar) New(value uint64) curves.Scalar {
	return &Scalar{
		Value: new(fq.Fq).SetUint64(value),
	}
}

func (s *Scalar) Cmp(rhs curves.Scalar) int {
	r, ok := rhs.(*Scalar)
	if ok {
		gt, eq, _ := s.Nat().Cmp(r.Nat())
		return (int(gt) + int(gt) + int(eq)) - 1
	} else {
		return -2
	}
}

func (s *Scalar) Square() curves.Scalar {
	return &Scalar{
		Value: new(fq.Fq).Square(s.Value),
	}
}

func (s *Scalar) Double() curves.Scalar {
	return &Scalar{
		Value: new(fq.Fq).Double(s.Value),
	}
}

func (s *Scalar) Invert() (curves.Scalar, error) {
	value, wasInverted := new(fq.Fq).Invert(s.Value)
	if !wasInverted {
		return nil, errs.NewFailed("inverse doesn't exist")
	}
	return &Scalar{
		Value: value,
	}, nil
}

func (s *Scalar) Sqrt() (curves.Scalar, error) {
	value, wasSquare := new(fq.Fq).Sqrt(s.Value)
	if !wasSquare {
		return nil, errs.NewFailed("not a square")
	}
	return &Scalar{
		Value: value,
	}, nil
}

func (s *Scalar) Cube() curves.Scalar {
	value := new(fq.Fq).Mul(s.Value, s.Value)
	value.Mul(value, s.Value)
	return &Scalar{
		Value: value,
	}
}

func (s *Scalar) Add(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			Value: new(fq.Fq).Add(s.Value, r.Value),
		}
	} else {
		panic("rhs is not a pallas scalar")
	}
}

func (s *Scalar) Sub(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			Value: new(fq.Fq).Sub(s.Value, r.Value),
		}
	} else {
		panic("rhs is not a pallas scalar")
	}
}

func (s *Scalar) Mul(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			Value: new(fq.Fq).Mul(s.Value, r.Value),
		}
	} else {
		panic("rhs is not a pallas scalar")
	}
}

func (s *Scalar) MulAdd(y, z curves.Scalar) curves.Scalar {
	return s.Mul(y).Add(z)
}

func (s *Scalar) Div(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		v, wasInverted := new(fq.Fq).Invert(r.Value)
		if !wasInverted {
			panic("cannot invert rhs")
		}
		v.Mul(v, s.Value)
		return &Scalar{Value: v}
	} else {
		panic("rhs is not a pallas scalar")
	}
}

func (s *Scalar) Exp(k curves.Scalar) curves.Scalar {
	exponent, ok := k.(*Scalar)
	if !ok {
		panic("k is not a pallas scalar")
	}

	value := new(fq.Fq).Exp(s.Value, exponent.Value)
	return &Scalar{Value: value}
}

func (s *Scalar) Neg() curves.Scalar {
	return &Scalar{
		Value: new(fq.Fq).Neg(s.Value),
	}
}

func (*Scalar) SetNat(v *saferith.Nat) (curves.Scalar, error) {
	return &Scalar{
		Value: new(fq.Fq).SetNat(v),
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
	return t[:]
}

func (*Scalar) SetBytes(input []byte) (curves.Scalar, error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewInvalidLength("invalid length")
	}
	value, err := new(fq.Fq).SetBytes((*[base.FieldBytes]byte)(input))
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set bytes")
	}
	return &Scalar{
		Value: value,
	}, nil
}

func (*Scalar) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) > base.WideFieldBytes {
		return nil, errs.NewInvalidLength("invalid length %d > %d bytes", len(input), base.WideFieldBytes)
	}
	input = bitstring.ReverseAndPadBytes(input, base.WideFieldBytes-len(input))
	return &Scalar{
		Value: new(fq.Fq).SetBytesWide((*[base.WideFieldBytes]byte)(input)),
	}, nil
}

func (s *Scalar) Clone() curves.Scalar {
	return &Scalar{
		Value: new(fq.Fq).Set(s.Value),
	}
}

func (s *Scalar) GetFq() *fq.Fq {
	return new(fq.Fq).Set(s.Value)
}

func (s *Scalar) SetFq(element *fq.Fq) *Scalar {
	s.Value = element
	return s
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
		return errs.WrapSerializationError(err, "could not unmarshal binary")
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
		return errs.WrapSerializationError(err, "could not unmarshal text")
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewInvalidLength("invalid scalar")
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
