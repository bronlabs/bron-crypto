package pallas

import (
	"bytes"
	"io"
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/pallas/impl/fq"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var _ (curves.Scalar) = (*Scalar)(nil)

type Scalar struct {
	value *fq.Fq

	_ helper_types.Incomparable
}

func (Scalar) Curve() (curves.Curve, error) {
	return pallasInstance, nil
}

func (Scalar) CurveName() string {
	return Name
}

func (s *Scalar) Random(reader io.Reader) curves.Scalar {
	if reader == nil {
		return nil
	}
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return s.Hash(seed[:])
}

func (*Scalar) Hash(inputs ...[]byte) curves.Scalar {
	xmd := impl.ExpandMsgXmd(impl.EllipticPointHasherBlake2b(), bytes.Join(inputs, nil), []byte("pallas_XMD:BLAKE2b_SSWU_RO_"), 64)
	var t [64]byte
	copy(t[:], xmd)
	return &Scalar{
		value: new(fq.Fq).SetBytesWide(&t),
	}
}

func (*Scalar) Zero() curves.Scalar {
	return &Scalar{
		value: new(fq.Fq).SetZero(),
	}
}

func (*Scalar) One() curves.Scalar {
	return &Scalar{
		value: new(fq.Fq).SetOne(),
	}
}

func (s *Scalar) IsZero() bool {
	return s.value.IsZero()
}

func (s *Scalar) IsOne() bool {
	return s.value.IsOne()
}

func (s *Scalar) IsOdd() bool {
	return (s.value[0] & 1) == 1
}

func (s *Scalar) IsEven() bool {
	return (s.value[0] & 1) == 0
}

func (*Scalar) New(value int) curves.Scalar {
	v := big.NewInt(int64(value))
	return &Scalar{
		value: new(fq.Fq).SetBigInt(v),
	}
}

func (s *Scalar) Cmp(rhs curves.Scalar) int {
	r, ok := rhs.(*Scalar)
	if ok {
		return s.value.Cmp(r.value)
	} else {
		return -2
	}
}

func (s *Scalar) Square() curves.Scalar {
	return &Scalar{
		value: new(fq.Fq).Square(s.value),
	}
}

func (s *Scalar) Double() curves.Scalar {
	return &Scalar{
		value: new(fq.Fq).Double(s.value),
	}
}

func (s *Scalar) Invert() (curves.Scalar, error) {
	value, wasInverted := new(fq.Fq).Invert(s.value)
	if !wasInverted {
		return nil, errs.NewFailed("inverse doesn't exist")
	}
	return &Scalar{
		value: value,
	}, nil
}

func (s *Scalar) Sqrt() (curves.Scalar, error) {
	value, wasSquare := new(fq.Fq).Sqrt(s.value)
	if !wasSquare {
		return nil, errs.NewFailed("not a square")
	}
	return &Scalar{
		value: value,
	}, nil
}

func (s *Scalar) Cube() curves.Scalar {
	value := new(fq.Fq).Mul(s.value, s.value)
	value.Mul(value, s.value)
	return &Scalar{
		value: value,
	}
}

func (s *Scalar) Add(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			value: new(fq.Fq).Add(s.value, r.value),
		}
	} else {
		return nil
	}
}

func (s *Scalar) Sub(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			value: new(fq.Fq).Sub(s.value, r.value),
		}
	} else {
		return nil
	}
}

func (s *Scalar) Mul(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			value: new(fq.Fq).Mul(s.value, r.value),
		}
	} else {
		return nil
	}
}

func (s *Scalar) MulAdd(y, z curves.Scalar) curves.Scalar {
	return s.Mul(y).Add(z)
}

func (s *Scalar) Div(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		v, wasInverted := new(fq.Fq).Invert(r.value)
		if !wasInverted {
			return nil
		}
		v.Mul(v, s.value)
		return &Scalar{value: v}
	} else {
		return nil
	}
}

func (s *Scalar) Exp(k curves.Scalar) curves.Scalar {
	exponent, ok := k.(*Scalar)
	if !ok {
		return nil
	}

	value := new(fq.Fq).Exp(s.value, exponent.value)
	return &Scalar{value: value}
}

func (s *Scalar) Neg() curves.Scalar {
	return &Scalar{
		value: new(fq.Fq).Neg(s.value),
	}
}

func (*Scalar) SetBigInt(v *big.Int) (curves.Scalar, error) {
	return &Scalar{
		value: new(fq.Fq).SetBigInt(v),
	}, nil
}

func (s *Scalar) BigInt() *big.Int {
	return s.value.BigInt()
}

func (s *Scalar) Bytes() []byte {
	t := s.value.Bytes()
	return t[:]
}

func (*Scalar) SetBytes(input []byte) (curves.Scalar, error) {
	if len(input) != 32 {
		return nil, errs.NewInvalidLength("invalid length")
	}
	var seq [32]byte
	copy(seq[:], input)
	value, err := new(fq.Fq).SetBytes(&seq)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set bytes")
	}
	return &Scalar{
		value: value,
	}, nil
}

func (*Scalar) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) != 64 {
		return nil, errs.NewInvalidLength("invalid length")
	}
	var seq [64]byte
	copy(seq[:], input)
	return &Scalar{
		value: new(fq.Fq).SetBytesWide(&seq),
	}, nil
}

func (s *Scalar) Clone() curves.Scalar {
	return &Scalar{
		value: new(fq.Fq).Set(s.value),
	}
}

func (s *Scalar) GetFq() *fq.Fq {
	return new(fq.Fq).Set(s.value)
}

func (s *Scalar) SetFq(element *fq.Fq) *Scalar {
	s.value = element
	return s
}

func (s *Scalar) MarshalBinary() ([]byte, error) {
	return internal.ScalarMarshalBinary(s)
}

func (s *Scalar) UnmarshalBinary(input []byte) error {
	sc, err := internal.ScalarUnmarshalBinary(Name, s.SetBytes, input)
	if err != nil {
		return errs.WrapDeserializationFailed(err, "could not unmarshal binary")
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.value = ss.value
	return nil
}

func (s *Scalar) MarshalText() ([]byte, error) {
	return internal.ScalarMarshalText(s)
}

func (s *Scalar) UnmarshalText(input []byte) error {
	sc, err := internal.ScalarUnmarshalText(Name, s.SetBytes, input)
	if err != nil {
		return errs.WrapDeserializationFailed(err, "could not unmarshal text")
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewInvalidLength("invalid scalar")
	}
	s.value = ss.value
	return nil
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
	s.value = S.value
	return nil
}
