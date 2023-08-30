package p256

import (
	"bytes"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256/impl/fq"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var _ (curves.Scalar) = (*ScalarP256)(nil)

type ScalarP256 struct {
	Value *impl.Field

	_ helper_types.Incomparable
}

func (*ScalarP256) Curve() curves.Curve {
	return &p256Instance
}

func (*ScalarP256) CurveName() string {
	return Name
}

func (s *ScalarP256) Random(prng io.Reader) curves.Scalar {
	if prng == nil {
		panic("prng is nil")
	}
	var seed [64]byte
	_, _ = prng.Read(seed[:])
	return s.Hash(seed[:])
}

func (*ScalarP256) Hash(inputs ...[]byte) curves.Scalar {
	dst := []byte("P256_XMD:SHA-256_SSWU_RO_")
	xmd := impl.ExpandMsgXmd(impl.EllipticPointHasherSha256(), bytes.Join(inputs, nil), dst, 48)
	var t [64]byte
	copy(t[:48], bitstring.ReverseBytes(xmd))

	return &ScalarP256{
		Value: fq.New().SetBytesWide(&t),
	}
}

func (*ScalarP256) Zero() curves.Scalar {
	return &ScalarP256{
		Value: fq.New().SetZero(),
	}
}

func (*ScalarP256) One() curves.Scalar {
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

func (*ScalarP256) New(value uint64) curves.Scalar {
	return &ScalarP256{
		Value: fq.New().SetUint64(value),
	}
}

func (s *ScalarP256) Cmp(rhs curves.Scalar) int {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*ScalarP256)
	if ok {
		return s.Value.Cmp(r.Value)
	} else {
		panic("rhs is not Scalar")
	}
}

func (s *ScalarP256) Square() curves.Scalar {
	return &ScalarP256{
		Value: fq.New().Square(s.Value),
	}
}

func (s *ScalarP256) Double() curves.Scalar {
	return &ScalarP256{
		Value: fq.New().Double(s.Value),
	}
}

func (s *ScalarP256) Invert() (curves.Scalar, error) {
	value, wasInverted := fq.New().Invert(s.Value)
	if !wasInverted {
		return nil, errs.NewFailed("inverse doesn't exist")
	}
	return &ScalarP256{
		Value: value,
	}, nil
}

func (s *ScalarP256) Sqrt() (curves.Scalar, error) {
	value, wasSquare := fq.New().Sqrt(s.Value)
	if !wasSquare {
		return nil, errs.NewFailed("not a square")
	}
	return &ScalarP256{
		Value: value,
	}, nil
}

func (s *ScalarP256) Cube() curves.Scalar {
	value := fq.New().Mul(s.Value, s.Value)
	value.Mul(value, s.Value)
	return &ScalarP256{
		Value: value,
	}
}

func (s *ScalarP256) Add(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarP256)
	if ok {
		return &ScalarP256{
			Value: fq.New().Add(s.Value, r.Value),
		}
	} else {
		panic("rhs is not Scalar")
	}
}

func (s *ScalarP256) Sub(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarP256)
	if ok {
		return &ScalarP256{
			Value: fq.New().Sub(s.Value, r.Value),
		}
	} else {
		panic("rhs is not Scalar")
	}
}

func (s *ScalarP256) Mul(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarP256)
	if ok {
		return &ScalarP256{
			Value: fq.New().Mul(s.Value, r.Value),
		}
	} else {
		panic("rhs is not Scalar")
	}
}

func (s *ScalarP256) MulAdd(y, z curves.Scalar) curves.Scalar {
	return s.Mul(y).Add(z)
}

func (s *ScalarP256) Div(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarP256)
	if ok {
		v, wasInverted := fq.New().Invert(r.Value)
		if !wasInverted {
			panic("cannot invert scalar")
		}
		v.Mul(v, s.Value)
		return &ScalarP256{Value: v}
	} else {
		panic("rhs is not Scalar")
	}
}

func (s *ScalarP256) Exp(k curves.Scalar) curves.Scalar {
	exponent, ok := k.(*ScalarP256)
	if !ok {
		panic("rhs is not Scalar")
	}

	value := fq.New().Exp(s.Value, exponent.Value)
	return &ScalarP256{Value: value}
}

func (s *ScalarP256) Neg() curves.Scalar {
	return &ScalarP256{
		Value: fq.New().Neg(s.Value),
	}
}

func (*ScalarP256) SetNat(v *saferith.Nat) (curves.Scalar, error) {
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

func (*ScalarP256) SetBytes(input []byte) (curves.Scalar, error) {
	if len(input) != 32 {
		return nil, errs.NewInvalidLength("invalid length")
	}
	var seq [32]byte
	copy(seq[:], bitstring.ReverseBytes(input))
	value, err := fq.New().SetBytes(&seq)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set bytes")
	}
	return &ScalarP256{
		Value: value,
	}, nil
}

func (*ScalarP256) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) != 64 {
		return nil, errs.NewInvalidLength("invalid length")
	}
	var seq [64]byte
	copy(seq[:], input)
	return &ScalarP256{
		Value: fq.New().SetBytesWide(&seq),
	}, nil
}

func (s *ScalarP256) Clone() curves.Scalar {
	return &ScalarP256{
		Value: fq.New().Set(s.Value),
	}
}

func (s *ScalarP256) MarshalBinary() ([]byte, error) {
	return internal.ScalarMarshalBinary(s)
}

func (s *ScalarP256) UnmarshalBinary(input []byte) error {
	sc, err := internal.ScalarUnmarshalBinary(Name, s.SetBytes, input)
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
	return internal.ScalarMarshalText(s)
}

func (s *ScalarP256) UnmarshalText(input []byte) error {
	sc, err := internal.ScalarUnmarshalText(Name, s.SetBytes, input)
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
	return internal.ScalarMarshalJson(Name, s)
}

func (s *ScalarP256) UnmarshalJSON(input []byte) error {
	sc, err := internal.NewScalarFromJSON(s.SetBytes, input)
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
