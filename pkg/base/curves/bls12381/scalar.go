package bls12381

import (
	"bytes"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton/pkg/base/bitstring"
	"github.com/copperexchange/krypton/pkg/base/curves"
	bls12381impl "github.com/copperexchange/krypton/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/krypton/pkg/base/curves/impl"
	"github.com/copperexchange/krypton/pkg/base/curves/internal"
	"github.com/copperexchange/krypton/pkg/base/errs"
	"github.com/copperexchange/krypton/pkg/base/types"
)

var _ curves.PairingScalar = (*Scalar)(nil)

type Scalar struct {
	Value  *impl.Field
	Point_ curves.PairingPoint

	_ types.Incomparable
}

func (s *Scalar) Curve() curves.Curve {
	curve := s.Point().Curve()
	return curve
}

func (s *Scalar) CurveName() string {
	return s.Point().CurveName()
}

func (*Scalar) PairingCurve() curves.PairingCurve {
	return New()
}

func (*Scalar) PairingCurveName() string {
	return Name
}

func (s *Scalar) Random(prng io.Reader) curves.Scalar {
	if prng == nil {
		panic("prng in nil")
	}
	var seed [64]byte
	_, _ = prng.Read(seed[:])
	return s.Hash(seed[:])
}

func (s *Scalar) Hash(inputs ...[]byte) curves.Scalar {
	dst := []byte("BLS12381_XMD:SHA-256_SSWU_RO_")
	xmd := impl.ExpandMsgXmd(impl.EllipticPointHasherSha256(), bytes.Join(inputs, nil), dst, 48)
	var t [64]byte
	copy(t[:48], bitstring.ReverseBytes(xmd))

	return &Scalar{
		Value:  bls12381impl.FqNew().SetBytesWide(&t),
		Point_: s.Point_,
	}
}

func (s *Scalar) Zero() curves.Scalar {
	return &Scalar{
		Value:  bls12381impl.FqNew().SetZero(),
		Point_: s.Point_,
	}
}

func (s *Scalar) One() curves.Scalar {
	return &Scalar{
		Value:  bls12381impl.FqNew().SetOne(),
		Point_: s.Point_,
	}
}

func (s *Scalar) IsZero() bool {
	return s.Value.IsZero() == 1
}

func (s *Scalar) IsOne() bool {
	return s.Value.IsOne() == 1
}

func (s *Scalar) IsOdd() bool {
	bytes_ := s.Value.Bytes()
	return bytes_[0]&1 == 1
}

func (s *Scalar) IsEven() bool {
	bytes_ := s.Value.Bytes()
	return bytes_[0]&1 == 0
}

func (s *Scalar) New(value uint64) curves.Scalar {
	return &Scalar{
		Value:  bls12381impl.FqNew().SetUint64(value),
		Point_: s.Point_,
	}
}

func (s *Scalar) Cmp(rhs curves.Scalar) int {
	r, ok := rhs.(*Scalar)
	if ok {
		return s.Value.Cmp(r.Value)
	} else {
		return -2
	}
}

func (s *Scalar) Square() curves.Scalar {
	return &Scalar{
		Value:  bls12381impl.FqNew().Square(s.Value),
		Point_: s.Point_,
	}
}

func (s *Scalar) Double() curves.Scalar {
	v := bls12381impl.FqNew().Double(s.Value)
	return &Scalar{
		Value:  v,
		Point_: s.Point_,
	}
}

func (s *Scalar) Invert() (curves.Scalar, error) {
	value, wasInverted := bls12381impl.FqNew().Invert(s.Value)
	if !wasInverted {
		return nil, errs.NewFailed("inverse doesn't exist")
	}
	return &Scalar{
		Value:  value,
		Point_: s.Point_,
	}, nil
}

func (s *Scalar) Sqrt() (curves.Scalar, error) {
	value, wasSquare := bls12381impl.FqNew().Sqrt(s.Value)
	if !wasSquare {
		return nil, errs.NewFailed("not a square")
	}
	return &Scalar{
		Value:  value,
		Point_: s.Point_,
	}, nil
}

func (s *Scalar) Cube() curves.Scalar {
	value := bls12381impl.FqNew().Square(s.Value)
	value.Mul(value, s.Value)
	return &Scalar{
		Value:  value,
		Point_: s.Point_,
	}
}

func (s *Scalar) Add(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			Value:  bls12381impl.FqNew().Add(s.Value, r.Value),
			Point_: s.Point_,
		}
	} else {
		panic("rhs is not ScalarBls12381")
	}
}

func (s *Scalar) Sub(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			Value:  bls12381impl.FqNew().Sub(s.Value, r.Value),
			Point_: s.Point_,
		}
	} else {
		panic("rhs is not ScalarBls12381")
	}
}

func (s *Scalar) Mul(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			Value:  bls12381impl.FqNew().Mul(s.Value, r.Value),
			Point_: s.Point_,
		}
	} else {
		panic("rhs is not ScalarBls12381")
	}
}

func (s *Scalar) MulAdd(y, z curves.Scalar) curves.Scalar {
	return s.Mul(y).Add(z)
}

func (s *Scalar) Div(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		v, wasInverted := bls12381impl.FqNew().Invert(r.Value)
		if !wasInverted {
			panic("cannot invert scalar")
		}
		v.Mul(v, s.Value)
		return &Scalar{
			Value:  v,
			Point_: s.Point_,
		}
	} else {
		panic("rhs is not ScalarBls12381")
	}
}

func (s *Scalar) Exp(k curves.Scalar) curves.Scalar {
	exp, ok := k.(*Scalar)
	if !ok {
		panic("rhs is not ScalarBls12381")
	}

	value := bls12381impl.FqNew().Exp(s.Value, exp.Value)
	return &Scalar{
		Value:  value,
		Point_: s.Point_,
	}
}

func (s *Scalar) Neg() curves.Scalar {
	return &Scalar{
		Value:  bls12381impl.FqNew().Neg(s.Value),
		Point_: s.Point_,
	}
}

func (s *Scalar) SetNat(v *saferith.Nat) (curves.Scalar, error) {
	if v == nil {
		return nil, errs.NewFailed("invalid value")
	}
	return &Scalar{
		Value:  bls12381impl.FqNew().SetNat(v),
		Point_: s.Point_,
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

func (s *Scalar) SetBytes(input []byte) (curves.Scalar, error) {
	if len(input) != 32 {
		return nil, errs.NewInvalidLength("invalid length")
	}
	var seq [32]byte
	copy(seq[:], bitstring.ReverseBytes(input))
	value, err := bls12381impl.FqNew().SetBytes(&seq)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "couldn't set bytes")
	}
	return &Scalar{
		Value: value, Point_: s.Point_,
	}, nil
}

func (s *Scalar) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) != 64 {
		return nil, errs.NewInvalidLength("invalid length")
	}
	var seq [64]byte
	copy(seq[:], input)
	return &Scalar{
		Value: bls12381impl.FqNew().SetBytesWide(&seq), Point_: s.Point_,
	}, nil
}

func (s *Scalar) Clone() curves.Scalar {
	return &Scalar{
		Value:  bls12381impl.FqNew().Set(s.Value),
		Point_: s.Point_,
	}
}

func (s *Scalar) OtherGroup() curves.PairingPoint {
	return s.Point_.OtherGroup()
}

func (s *Scalar) Point() curves.PairingPoint {
	return s.Point_
}

func (s *Scalar) SetPoint(p curves.PairingPoint) curves.PairingScalar {
	return &Scalar{
		Value:  bls12381impl.FqNew().Set(s.Value),
		Point_: p,
	}
}

func (s *Scalar) Order() *saferith.Modulus {
	return s.Value.Params.Modulus
}

func (s *Scalar) MarshalBinary() ([]byte, error) {
	result, err := internal.ScalarMarshalBinary(s)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "couldn't marshal to binary")
	}
	return result, nil
}

func (s *Scalar) UnmarshalBinary(input []byte) error {
	curve := s.Curve()
	sc, err := internal.ScalarUnmarshalBinary(curve.Name(), s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	s.Point_ = ss.Point_
	return nil
}

func (s *Scalar) MarshalText() ([]byte, error) {
	result, err := internal.ScalarMarshalText(s)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "couldn't marshal to text")
	}
	return result, nil
}

func (s *Scalar) UnmarshalText(input []byte) error {
	curve := s.Curve()
	sc, err := internal.ScalarUnmarshalText(curve.Name(), s.SetBytes, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.Value = ss.Value
	s.Point_ = ss.Point_
	return nil
}

func (s *Scalar) MarshalJSON() ([]byte, error) {
	curve := s.Curve()
	result, err := internal.ScalarMarshalJson(curve.Name(), s)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "couldn't marshal json")
	}
	return result, nil
}

func (s *Scalar) UnmarshalJSON(input []byte) error {
	sc, err := internal.NewScalarFromJSON(s.SetBytes, input)
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
