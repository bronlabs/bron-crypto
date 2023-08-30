package bls12381

import (
	"bytes"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	bls12381impl "github.com/copperexchange/knox-primitives/pkg/core/curves/bls12381/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var _ curves.PairingScalar = (*ScalarBls12381)(nil)

type ScalarBls12381 struct {
	Value  *impl.Field
	Point_ curves.PairingPoint

	_ helper_types.Incomparable
}

func (s *ScalarBls12381) Curve() curves.Curve {
	curve := s.Point().Curve()
	return curve
}

func (s *ScalarBls12381) CurveName() string {
	return s.Point().CurveName()
}

func (*ScalarBls12381) PairingCurve() curves.PairingCurve {
	return New()
}

func (*ScalarBls12381) PairingCurveName() string {
	return Name
}

func (s *ScalarBls12381) Random(prng io.Reader) curves.Scalar {
	if prng == nil {
		panic("prng in nil")
	}
	var seed [64]byte
	_, _ = prng.Read(seed[:])
	return s.Hash(seed[:])
}

func (s *ScalarBls12381) Hash(inputs ...[]byte) curves.Scalar {
	dst := []byte("BLS12381_XMD:SHA-256_SSWU_RO_")
	xmd := impl.ExpandMsgXmd(impl.EllipticPointHasherSha256(), bytes.Join(inputs, nil), dst, 48)
	var t [64]byte
	copy(t[:48], bitstring.ReverseBytes(xmd))

	return &ScalarBls12381{
		Value:  bls12381impl.FqNew().SetBytesWide(&t),
		Point_: s.Point_,
	}
}

func (s *ScalarBls12381) Zero() curves.Scalar {
	return &ScalarBls12381{
		Value:  bls12381impl.FqNew().SetZero(),
		Point_: s.Point_,
	}
}

func (s *ScalarBls12381) One() curves.Scalar {
	return &ScalarBls12381{
		Value:  bls12381impl.FqNew().SetOne(),
		Point_: s.Point_,
	}
}

func (s *ScalarBls12381) IsZero() bool {
	return s.Value.IsZero() == 1
}

func (s *ScalarBls12381) IsOne() bool {
	return s.Value.IsOne() == 1
}

func (s *ScalarBls12381) IsOdd() bool {
	bytes_ := s.Value.Bytes()
	return bytes_[0]&1 == 1
}

func (s *ScalarBls12381) IsEven() bool {
	bytes_ := s.Value.Bytes()
	return bytes_[0]&1 == 0
}

func (s *ScalarBls12381) New(value uint64) curves.Scalar {
	return &ScalarBls12381{
		Value:  bls12381impl.FqNew().SetUint64(value),
		Point_: s.Point_,
	}
}

func (s *ScalarBls12381) Cmp(rhs curves.Scalar) int {
	r, ok := rhs.(*ScalarBls12381)
	if ok {
		return s.Value.Cmp(r.Value)
	} else {
		return -2
	}
}

func (s *ScalarBls12381) Square() curves.Scalar {
	return &ScalarBls12381{
		Value:  bls12381impl.FqNew().Square(s.Value),
		Point_: s.Point_,
	}
}

func (s *ScalarBls12381) Double() curves.Scalar {
	v := bls12381impl.FqNew().Double(s.Value)
	return &ScalarBls12381{
		Value:  v,
		Point_: s.Point_,
	}
}

func (s *ScalarBls12381) Invert() (curves.Scalar, error) {
	value, wasInverted := bls12381impl.FqNew().Invert(s.Value)
	if !wasInverted {
		return nil, errs.NewFailed("inverse doesn't exist")
	}
	return &ScalarBls12381{
		Value:  value,
		Point_: s.Point_,
	}, nil
}

func (s *ScalarBls12381) Sqrt() (curves.Scalar, error) {
	value, wasSquare := bls12381impl.FqNew().Sqrt(s.Value)
	if !wasSquare {
		return nil, errs.NewFailed("not a square")
	}
	return &ScalarBls12381{
		Value:  value,
		Point_: s.Point_,
	}, nil
}

func (s *ScalarBls12381) Cube() curves.Scalar {
	value := bls12381impl.FqNew().Square(s.Value)
	value.Mul(value, s.Value)
	return &ScalarBls12381{
		Value:  value,
		Point_: s.Point_,
	}
}

func (s *ScalarBls12381) Add(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarBls12381)
	if ok {
		return &ScalarBls12381{
			Value:  bls12381impl.FqNew().Add(s.Value, r.Value),
			Point_: s.Point_,
		}
	} else {
		panic("rhs is not ScalarBls12381")
	}
}

func (s *ScalarBls12381) Sub(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarBls12381)
	if ok {
		return &ScalarBls12381{
			Value:  bls12381impl.FqNew().Sub(s.Value, r.Value),
			Point_: s.Point_,
		}
	} else {
		panic("rhs is not ScalarBls12381")
	}
}

func (s *ScalarBls12381) Mul(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarBls12381)
	if ok {
		return &ScalarBls12381{
			Value:  bls12381impl.FqNew().Mul(s.Value, r.Value),
			Point_: s.Point_,
		}
	} else {
		panic("rhs is not ScalarBls12381")
	}
}

func (s *ScalarBls12381) MulAdd(y, z curves.Scalar) curves.Scalar {
	return s.Mul(y).Add(z)
}

func (s *ScalarBls12381) Div(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*ScalarBls12381)
	if ok {
		v, wasInverted := bls12381impl.FqNew().Invert(r.Value)
		if !wasInverted {
			panic("cannot invert scalar")
		}
		v.Mul(v, s.Value)
		return &ScalarBls12381{
			Value:  v,
			Point_: s.Point_,
		}
	} else {
		panic("rhs is not ScalarBls12381")
	}
}

func (s *ScalarBls12381) Exp(k curves.Scalar) curves.Scalar {
	exp, ok := k.(*ScalarBls12381)
	if !ok {
		panic("rhs is not ScalarBls12381")
	}

	value := bls12381impl.FqNew().Exp(s.Value, exp.Value)
	return &ScalarBls12381{
		Value:  value,
		Point_: s.Point_,
	}
}

func (s *ScalarBls12381) Neg() curves.Scalar {
	return &ScalarBls12381{
		Value:  bls12381impl.FqNew().Neg(s.Value),
		Point_: s.Point_,
	}
}

func (s *ScalarBls12381) SetNat(v *saferith.Nat) (curves.Scalar, error) {
	if v == nil {
		return nil, errs.NewFailed("invalid value")
	}
	return &ScalarBls12381{
		Value:  bls12381impl.FqNew().SetNat(v),
		Point_: s.Point_,
	}, nil
}

func (s *ScalarBls12381) Nat() *saferith.Nat {
	return s.Value.Nat()
}

func (s *ScalarBls12381) Uint64() uint64 {
	return s.Nat().Big().Uint64()
}

func (s *ScalarBls12381) Bytes() []byte {
	t := s.Value.Bytes()
	return bitstring.ReverseBytes(t[:])
}

func (s *ScalarBls12381) SetBytes(input []byte) (curves.Scalar, error) {
	if len(input) != 32 {
		return nil, errs.NewInvalidLength("invalid length")
	}
	var seq [32]byte
	copy(seq[:], bitstring.ReverseBytes(input))
	value, err := bls12381impl.FqNew().SetBytes(&seq)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "couldn't set bytes")
	}
	return &ScalarBls12381{
		Value: value, Point_: s.Point_,
	}, nil
}

func (s *ScalarBls12381) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) != 64 {
		return nil, errs.NewInvalidLength("invalid length")
	}
	var seq [64]byte
	copy(seq[:], input)
	return &ScalarBls12381{
		Value: bls12381impl.FqNew().SetBytesWide(&seq), Point_: s.Point_,
	}, nil
}

func (s *ScalarBls12381) Clone() curves.Scalar {
	return &ScalarBls12381{
		Value:  bls12381impl.FqNew().Set(s.Value),
		Point_: s.Point_,
	}
}

func (s *ScalarBls12381) OtherGroup() curves.PairingPoint {
	return s.Point_.OtherGroup()
}

func (s *ScalarBls12381) Point() curves.PairingPoint {
	return s.Point_
}

func (s *ScalarBls12381) SetPoint(p curves.PairingPoint) curves.PairingScalar {
	return &ScalarBls12381{
		Value:  bls12381impl.FqNew().Set(s.Value),
		Point_: p,
	}
}

func (s *ScalarBls12381) Order() *saferith.Modulus {
	return s.Value.Params.Modulus
}

func (s *ScalarBls12381) MarshalBinary() ([]byte, error) {
	result, err := internal.ScalarMarshalBinary(s)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "couldn't marshal to binary")
	}
	return result, nil
}

func (s *ScalarBls12381) UnmarshalBinary(input []byte) error {
	curve := s.Curve()
	sc, err := internal.ScalarUnmarshalBinary(curve.Name(), s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ss, ok := sc.(*ScalarBls12381)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	s.Point_ = ss.Point_
	return nil
}

func (s *ScalarBls12381) MarshalText() ([]byte, error) {
	result, err := internal.ScalarMarshalText(s)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "couldn't marshal to text")
	}
	return result, nil
}

func (s *ScalarBls12381) UnmarshalText(input []byte) error {
	curve := s.Curve()
	sc, err := internal.ScalarUnmarshalText(curve.Name(), s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ss, ok := sc.(*ScalarBls12381)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	s.Point_ = ss.Point_
	return nil
}

func (s *ScalarBls12381) MarshalJSON() ([]byte, error) {
	curve := s.Curve()
	result, err := internal.ScalarMarshalJson(curve.Name(), s)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "couldn't marshal json")
	}
	return result, nil
}

func (s *ScalarBls12381) UnmarshalJSON(input []byte) error {
	sc, err := internal.NewScalarFromJSON(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not extract a scalar from json")
	}
	S, ok := sc.(*ScalarBls12381)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.Value = S.Value
	return nil
}
