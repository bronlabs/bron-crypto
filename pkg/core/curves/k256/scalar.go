package k256

import (
	"bytes"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256/impl/fq"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var _ curves.Scalar = (*ScalarK256)(nil)

type ScalarK256 struct {
	Value *impl.Field

	_ helper_types.Incomparable
}

func (*ScalarK256) Curve() curves.Curve {
	return &k256Instance
}

func (s *ScalarK256) Random(prng io.Reader) curves.Scalar {
	if prng == nil {
		panic("prng is nil")
	}
	var seed [64]byte
	_, _ = prng.Read(seed[:])
	return s.Hash(seed[:])
}

func (*ScalarK256) Hash(inputs ...[]byte) curves.Scalar {
	dst := []byte("secp256k1_XMD:SHA-256_SSWU_RO_")
	xmd := impl.ExpandMsgXmd(impl.EllipticPointHasherSha256(), bytes.Join(inputs, nil), dst, 48)
	var t [64]byte
	copy(t[:48], bitstring.ReverseBytes(xmd))

	return &ScalarK256{
		Value: fq.New().SetBytesWide(&t),
	}
}

func (*ScalarK256) Zero() curves.Scalar {
	return &ScalarK256{
		Value: fq.New().SetZero(),
	}
}

func (*ScalarK256) One() curves.Scalar {
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

func (*ScalarK256) New(value uint64) curves.Scalar {
	return &ScalarK256{
		Value: fq.New().SetUint64(value),
	}
}

func (s *ScalarK256) Cmp(rhs curves.Scalar) int {
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

func (s *ScalarK256) Square() curves.Scalar {
	return &ScalarK256{
		Value: fq.New().Square(s.Value),
	}
}

func (s *ScalarK256) Double() curves.Scalar {
	return &ScalarK256{
		Value: fq.New().Double(s.Value),
	}
}

func (s *ScalarK256) Invert() (curves.Scalar, error) {
	value, wasInverted := fq.New().Invert(s.Value)
	if !wasInverted {
		return nil, errs.NewFailed("inverse doesn't exist")
	}
	return &ScalarK256{
		Value: value,
	}, nil
}

func (s *ScalarK256) Sqrt() (curves.Scalar, error) {
	value, wasSquare := fq.New().Sqrt(s.Value)
	if !wasSquare {
		return nil, errs.NewFailed("not a square")
	}
	return &ScalarK256{
		Value: value,
	}, nil
}

func (s *ScalarK256) Cube() curves.Scalar {
	value := fq.New().Mul(s.Value, s.Value)
	value.Mul(value, s.Value)
	return &ScalarK256{
		Value: value,
	}
}

func (s *ScalarK256) Add(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarK256)
	if ok {
		return &ScalarK256{
			Value: fq.New().Add(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *ScalarK256) Sub(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarK256)
	if ok {
		return &ScalarK256{
			Value: fq.New().Sub(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *ScalarK256) Mul(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarK256)
	if ok {
		return &ScalarK256{
			Value: fq.New().Mul(s.Value, r.Value),
		}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *ScalarK256) MulAdd(y, z curves.Scalar) curves.Scalar {
	return s.Mul(y).Add(z)
}

func (s *ScalarK256) Div(rhs curves.Scalar) curves.Scalar {
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

func (s *ScalarK256) Exp(k curves.Scalar) curves.Scalar {
	exponent, ok := k.(*ScalarK256)
	if !ok {
		panic("rhs is not ScalarK256")
	}

	value := fq.New().Exp(s.Value, exponent.Value)
	return &ScalarK256{Value: value}
}

func (s *ScalarK256) Neg() curves.Scalar {
	return &ScalarK256{
		Value: fq.New().Neg(s.Value),
	}
}

func (*ScalarK256) SetNat(v *saferith.Nat) (curves.Scalar, error) {
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

func (s *ScalarK256) Bytes() []byte {
	t := s.Value.Bytes()
	return bitstring.ReverseBytes(t[:])
}

func (*ScalarK256) SetBytes(input []byte) (curves.Scalar, error) {
	if len(input) != 32 {
		return nil, errs.NewInvalidLength("invalid length")
	}
	var seq [32]byte
	copy(seq[:], bitstring.ReverseBytes(input))
	value, err := fq.New().SetBytes(&seq)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set bytes")
	}
	return &ScalarK256{
		Value: value,
	}, nil
}

func (*ScalarK256) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) != 64 {
		return nil, errs.NewInvalidLength("invalid length")
	}
	var seq [64]byte
	copy(seq[:], input)
	return &ScalarK256{
		Value: fq.New().SetBytesWide(&seq),
	}, nil
}

func (*ScalarK256) CurveName() string {
	return Name
}

func (s *ScalarK256) Clone() curves.Scalar {
	return &ScalarK256{
		Value: fq.New().Set(s.Value),
	}
}

func (s *ScalarK256) MarshalBinary() ([]byte, error) {
	return internal.ScalarMarshalBinary(s)
}

func (s *ScalarK256) UnmarshalBinary(input []byte) error {
	sc, err := internal.ScalarUnmarshalBinary(Name, s.SetBytes, input)
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
	return internal.ScalarMarshalText(s)
}

func (s *ScalarK256) UnmarshalText(input []byte) error {
	sc, err := internal.ScalarUnmarshalText(Name, s.SetBytes, input)
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
	return internal.ScalarMarshalJson(Name, s)
}

func (s *ScalarK256) UnmarshalJSON(input []byte) error {
	sc, err := internal.NewScalarFromJSON(s.SetBytes, input)
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
