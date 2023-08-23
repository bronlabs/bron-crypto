package pallas

import (
	"bytes"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/pallas/impl/fq"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var _ curves.Scalar = (*ScalarPallas)(nil)

type ScalarPallas struct {
	value *fq.Fq

	_ helper_types.Incomparable
}

func (*ScalarPallas) Curve() curves.Curve {
	return &pallasInstance
}

func (*ScalarPallas) CurveName() string {
	return Name
}

func (s *ScalarPallas) Random(reader io.Reader) curves.Scalar {
	if reader == nil {
		return nil
	}
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return s.Hash(seed[:])
}

func (*ScalarPallas) Hash(inputs ...[]byte) curves.Scalar {
	xmd := impl.ExpandMsgXmd(impl.EllipticPointHasherBlake2b(), bytes.Join(inputs, nil), []byte("pallas_XMD:BLAKE2b_SSWU_RO_"), 64)
	var t [64]byte
	copy(t[:], xmd)
	return &ScalarPallas{
		value: new(fq.Fq).SetBytesWide(&t),
	}
}

func (*ScalarPallas) Zero() curves.Scalar {
	return &ScalarPallas{
		value: new(fq.Fq).SetZero(),
	}
}

func (*ScalarPallas) One() curves.Scalar {
	return &ScalarPallas{
		value: new(fq.Fq).SetOne(),
	}
}

func (s *ScalarPallas) IsZero() bool {
	return s.value.IsZero()
}

func (s *ScalarPallas) IsOne() bool {
	return s.value.IsOne()
}

func (s *ScalarPallas) IsOdd() bool {
	return (s.value[0] & 1) == 1
}

func (s *ScalarPallas) IsEven() bool {
	return (s.value[0] & 1) == 0
}

func (*ScalarPallas) New(value uint64) curves.Scalar {
	v := new(saferith.Nat).SetUint64(value)
	return &ScalarPallas{
		value: new(fq.Fq).SetNat(v),
	}
}

func (s *ScalarPallas) Cmp(rhs curves.Scalar) int {
	r, ok := rhs.(*ScalarPallas)
	if ok {
		return s.value.Cmp(r.value)
	} else {
		return -2
	}
}

func (s *ScalarPallas) Square() curves.Scalar {
	return &ScalarPallas{
		value: new(fq.Fq).Square(s.value),
	}
}

func (s *ScalarPallas) Double() curves.Scalar {
	return &ScalarPallas{
		value: new(fq.Fq).Double(s.value),
	}
}

func (s *ScalarPallas) Invert() (curves.Scalar, error) {
	value, wasInverted := new(fq.Fq).Invert(s.value)
	if !wasInverted {
		return nil, errs.NewFailed("inverse doesn't exist")
	}
	return &ScalarPallas{
		value: value,
	}, nil
}

func (s *ScalarPallas) Sqrt() (curves.Scalar, error) {
	value, wasSquare := new(fq.Fq).Sqrt(s.value)
	if !wasSquare {
		return nil, errs.NewFailed("not a square")
	}
	return &ScalarPallas{
		value: value,
	}, nil
}

func (s *ScalarPallas) Cube() curves.Scalar {
	value := new(fq.Fq).Mul(s.value, s.value)
	value.Mul(value, s.value)
	return &ScalarPallas{
		value: value,
	}
}

func (s *ScalarPallas) Add(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarPallas)
	if ok {
		return &ScalarPallas{
			value: new(fq.Fq).Add(s.value, r.value),
		}
	} else {
		return nil
	}
}

func (s *ScalarPallas) Sub(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarPallas)
	if ok {
		return &ScalarPallas{
			value: new(fq.Fq).Sub(s.value, r.value),
		}
	} else {
		return nil
	}
}

func (s *ScalarPallas) Mul(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarPallas)
	if ok {
		return &ScalarPallas{
			value: new(fq.Fq).Mul(s.value, r.value),
		}
	} else {
		return nil
	}
}

func (s *ScalarPallas) MulAdd(y, z curves.Scalar) curves.Scalar {
	return s.Mul(y).Add(z)
}

func (s *ScalarPallas) Div(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarPallas)
	if ok {
		v, wasInverted := new(fq.Fq).Invert(r.value)
		if !wasInverted {
			return nil
		}
		v.Mul(v, s.value)
		return &ScalarPallas{value: v}
	} else {
		return nil
	}
}

func (s *ScalarPallas) Exp(k curves.Scalar) curves.Scalar {
	exponent, ok := k.(*ScalarPallas)
	if !ok {
		return nil
	}

	value := new(fq.Fq).Exp(s.value, exponent.value)
	return &ScalarPallas{value: value}
}

func (s *ScalarPallas) Neg() curves.Scalar {
	return &ScalarPallas{
		value: new(fq.Fq).Neg(s.value),
	}
}

func (*ScalarPallas) SetNat(v *saferith.Nat) (curves.Scalar, error) {
	return &ScalarPallas{
		value: new(fq.Fq).SetNat(v),
	}, nil
}

func (s *ScalarPallas) Nat() *saferith.Nat {
	return s.value.Nat()
}

func (s *ScalarPallas) Bytes() []byte {
	t := s.value.Bytes()
	return t[:]
}

func (*ScalarPallas) SetBytes(input []byte) (curves.Scalar, error) {
	if len(input) != 32 {
		return nil, errs.NewInvalidLength("invalid length")
	}
	var seq [32]byte
	copy(seq[:], input)
	value, err := new(fq.Fq).SetBytes(&seq)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set bytes")
	}
	return &ScalarPallas{
		value: value,
	}, nil
}

func (*ScalarPallas) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) != 64 {
		return nil, errs.NewInvalidLength("invalid length")
	}
	var seq [64]byte
	copy(seq[:], input)
	return &ScalarPallas{
		value: new(fq.Fq).SetBytesWide(&seq),
	}, nil
}

func (s *ScalarPallas) Clone() curves.Scalar {
	return &ScalarPallas{
		value: new(fq.Fq).Set(s.value),
	}
}

func (s *ScalarPallas) GetFq() *fq.Fq {
	return new(fq.Fq).Set(s.value)
}

func (s *ScalarPallas) SetFq(element *fq.Fq) *ScalarPallas {
	s.value = element
	return s
}

func (s *ScalarPallas) MarshalBinary() ([]byte, error) {
	return internal.ScalarMarshalBinary(s)
}

func (s *ScalarPallas) UnmarshalBinary(input []byte) error {
	sc, err := internal.ScalarUnmarshalBinary(Name, s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal binary")
	}
	ss, ok := sc.(*ScalarPallas)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.value = ss.value
	return nil
}

func (s *ScalarPallas) MarshalText() ([]byte, error) {
	return internal.ScalarMarshalText(s)
}

func (s *ScalarPallas) UnmarshalText(input []byte) error {
	sc, err := internal.ScalarUnmarshalText(Name, s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal text")
	}
	ss, ok := sc.(*ScalarPallas)
	if !ok {
		return errs.NewInvalidLength("invalid scalar")
	}
	s.value = ss.value
	return nil
}

func (s *ScalarPallas) MarshalJSON() ([]byte, error) {
	return internal.ScalarMarshalJson(Name, s)
}

func (s *ScalarPallas) UnmarshalJSON(input []byte) error {
	sc, err := internal.NewScalarFromJSON(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not extract a scalar from json")
	}
	S, ok := sc.(*ScalarPallas)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.value = S.value
	return nil
}
