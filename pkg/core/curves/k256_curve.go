//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package curves

import (
	"bytes"
	"crypto/elliptic"
	"io"
	"math/big"
	"reflect"
	"sync"

	"github.com/btcsuite/btcd/btcec"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/native"
	secp256k1 "github.com/copperexchange/knox-primitives/pkg/core/curves/native/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/native/k256/fp"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/native/k256/fq"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

var (
	oldK256Initonce sync.Once
	oldK256         Koblitz256
)

type Koblitz256 struct {
	*elliptic.CurveParams
}

func oldK256InitAll() {
	curve := btcec.S256()
	oldK256.CurveParams = new(elliptic.CurveParams)
	oldK256.P = curve.P
	oldK256.N = curve.N
	oldK256.Gx = curve.Gx
	oldK256.Gy = curve.Gy
	oldK256.B = curve.B
	oldK256.BitSize = curve.BitSize
	oldK256.Name = K256Name
}

func K256Curve() *Koblitz256 {
	oldK256Initonce.Do(oldK256InitAll)
	return &oldK256
}

func (curve *Koblitz256) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

func (*Koblitz256) IsOnCurve(x, y *big.Int) bool {
	_, err := secp256k1.PointNew().SetBigInt(x, y)
	return err == nil
}

func (*Koblitz256) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	p1, err := secp256k1.PointNew().SetBigInt(x1, y1)
	if err != nil {
		return nil, nil
	}
	p2, err := secp256k1.PointNew().SetBigInt(x2, y2)
	if err != nil {
		return nil, nil
	}
	return p1.Add(p1, p2).BigInt()
}

func (*Koblitz256) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	p1, err := secp256k1.PointNew().SetBigInt(x1, y1)
	if err != nil {
		return nil, nil
	}
	return p1.Double(p1).BigInt()
}

func (*Koblitz256) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	p1, err := secp256k1.PointNew().SetBigInt(Bx, By)
	if err != nil {
		panic(errs.WrapDeserializationFailed(err, "set big int"))
	}
	var bytes_ [32]byte
	copy(bytes_[:], bitstring.ReverseBytes(k))
	s, err := fq.K256FqNew().SetBytes(&bytes_)
	if err != nil {
		panic(errs.WrapDeserializationFailed(err, "set bytes"))
	}
	return p1.Mul(p1, s).BigInt()
}

func (*Koblitz256) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	var bytes_ [32]byte
	copy(bytes_[:], bitstring.ReverseBytes(k))
	s, err := fq.K256FqNew().SetBytes(&bytes_)
	if err != nil {
		panic(errs.WrapDeserializationFailed(err, "set bytes"))
	}
	p1 := secp256k1.PointNew().Generator()
	return p1.Mul(p1, s).BigInt()
}

type ScalarK256 struct {
	value *native.Field
}

type PointK256 struct {
	value *native.EllipticPoint
}

func (s *ScalarK256) Random(prng io.Reader) Scalar {
	if prng == nil {
		panic("prng is nil")
	}
	var seed [64]byte
	_, _ = prng.Read(seed[:])
	return s.Hash(seed[:])
}

func (*ScalarK256) Hash(inputs ...[]byte) Scalar {
	dst := []byte("secp256k1_XMD:SHA-256_SSWU_RO_")
	xmd := native.ExpandMsgXmd(native.EllipticPointHasherSha256(), bytes.Join(inputs, nil), dst, 48)
	var t [64]byte
	copy(t[:48], bitstring.ReverseBytes(xmd))

	return &ScalarK256{
		value: fq.K256FqNew().SetBytesWide(&t),
	}
}

func (*ScalarK256) Zero() Scalar {
	return &ScalarK256{
		value: fq.K256FqNew().SetZero(),
	}
}

func (*ScalarK256) One() Scalar {
	return &ScalarK256{
		value: fq.K256FqNew().SetOne(),
	}
}

func (s *ScalarK256) IsZero() bool {
	return s.value.IsZero() == 1
}

func (s *ScalarK256) IsOne() bool {
	return s.value.IsOne() == 1
}

func (s *ScalarK256) IsOdd() bool {
	return s.value.Bytes()[0]&1 == 1
}

func (s *ScalarK256) IsEven() bool {
	return s.value.Bytes()[0]&1 == 0
}

func (*ScalarK256) New(value int) Scalar {
	t := fq.K256FqNew()
	v := big.NewInt(int64(value))
	if value < 0 {
		v.Mod(v, t.Params.BiModulus)
	}
	return &ScalarK256{
		value: t.SetBigInt(v),
	}
}

func (s *ScalarK256) Cmp(rhs Scalar) int {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*ScalarK256)
	if ok {
		return s.value.Cmp(r.value)
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *ScalarK256) Square() Scalar {
	return &ScalarK256{
		value: fq.K256FqNew().Square(s.value),
	}
}

func (s *ScalarK256) Double() Scalar {
	return &ScalarK256{
		value: fq.K256FqNew().Double(s.value),
	}
}

func (s *ScalarK256) Invert() (Scalar, error) {
	value, wasInverted := fq.K256FqNew().Invert(s.value)
	if !wasInverted {
		return nil, errs.NewFailed("inverse doesn't exist")
	}
	return &ScalarK256{
		value,
	}, nil
}

func (s *ScalarK256) Sqrt() (Scalar, error) {
	value, wasSquare := fq.K256FqNew().Sqrt(s.value)
	if !wasSquare {
		return nil, errs.NewFailed("not a square")
	}
	return &ScalarK256{
		value,
	}, nil
}

func (s *ScalarK256) Cube() Scalar {
	value := fq.K256FqNew().Mul(s.value, s.value)
	value.Mul(value, s.value)
	return &ScalarK256{
		value,
	}
}

func (s *ScalarK256) Add(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarK256)
	if ok {
		return &ScalarK256{
			value: fq.K256FqNew().Add(s.value, r.value),
		}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *ScalarK256) Sub(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarK256)
	if ok {
		return &ScalarK256{
			value: fq.K256FqNew().Sub(s.value, r.value),
		}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *ScalarK256) Mul(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarK256)
	if ok {
		return &ScalarK256{
			value: fq.K256FqNew().Mul(s.value, r.value),
		}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *ScalarK256) MulAdd(y, z Scalar) Scalar {
	return s.Mul(y).Add(z)
}

func (s *ScalarK256) Div(rhs Scalar) Scalar {
	r, ok := rhs.(*ScalarK256)
	if ok {
		v, wasInverted := fq.K256FqNew().Invert(r.value)
		if !wasInverted {
			panic("cannot invert rhs")
		}
		v.Mul(v, s.value)
		return &ScalarK256{value: v}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (s *ScalarK256) Exp(k Scalar) Scalar {
	exponent, ok := k.(*ScalarK256)
	if !ok {
		panic("rhs is not ScalarK256")
	}

	value := fq.K256FqNew().Exp(s.value, exponent.value)
	return &ScalarK256{value}
}

func (s *ScalarK256) Neg() Scalar {
	return &ScalarK256{
		value: fq.K256FqNew().Neg(s.value),
	}
}

func (*ScalarK256) SetBigInt(v *big.Int) (Scalar, error) {
	if v == nil {
		return nil, errs.NewFailed("'v' cannot be nil")
	}
	value := fq.K256FqNew().SetBigInt(v)
	return &ScalarK256{
		value,
	}, nil
}

func (s *ScalarK256) BigInt() *big.Int {
	return s.value.BigInt()
}

func (s *ScalarK256) Bytes() []byte {
	t := s.value.Bytes()
	return bitstring.ReverseBytes(t[:])
}

func (*ScalarK256) SetBytes(input []byte) (Scalar, error) {
	if len(input) != 32 {
		return nil, errs.NewInvalidLength("invalid length")
	}
	var seq [32]byte
	copy(seq[:], bitstring.ReverseBytes(input))
	value, err := fq.K256FqNew().SetBytes(&seq)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set bytes")
	}
	return &ScalarK256{
		value,
	}, nil
}

func (*ScalarK256) SetBytesWide(input []byte) (Scalar, error) {
	if len(input) != 64 {
		return nil, errs.NewInvalidLength("invalid length")
	}
	var seq [64]byte
	copy(seq[:], input)
	return &ScalarK256{
		value: fq.K256FqNew().SetBytesWide(&seq),
	}, nil
}

func (*ScalarK256) CurveName() string {
	return K256Name
}

func (s *ScalarK256) Clone() Scalar {
	return &ScalarK256{
		value: fq.K256FqNew().Set(s.value),
	}
}

func (s *ScalarK256) MarshalBinary() ([]byte, error) {
	return scalarMarshalBinary(s)
}

func (s *ScalarK256) UnmarshalBinary(input []byte) error {
	sc, err := scalarUnmarshalBinary(input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*ScalarK256)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.value = ss.value
	return nil
}

func (s *ScalarK256) MarshalText() ([]byte, error) {
	return scalarMarshalText(s)
}

func (s *ScalarK256) UnmarshalText(input []byte) error {
	sc, err := scalarUnmarshalText(input)
	if err != nil {
		return err
	}
	ss, ok := sc.(*ScalarK256)
	if !ok {
		return errs.NewInvalidType("invalid scalar")
	}
	s.value = ss.value
	return nil
}

func (s *ScalarK256) MarshalJSON() ([]byte, error) {
	return scalarMarshalJson(s)
}

func (s *ScalarK256) UnmarshalJSON(input []byte) error {
	curve, err := GetCurveByName(s.CurveName())
	if err != nil {
		return errs.WrapDeserializationFailed(err, "json unmarshal failed")
	}
	sc, err := curve.NewScalarFromJSON(input)
	if err != nil {
		return errs.WrapFailed(err, "could not extract a scalar from json")
	}
	S, ok := sc.(*ScalarK256)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.value = S.value
	return nil
}

func (p *PointK256) Random(prng io.Reader) Point {
	var seed [64]byte
	_, _ = prng.Read(seed[:])
	return p.Hash(seed[:])
}

func (*PointK256) Hash(inputs ...[]byte) Point {
	value, err := secp256k1.PointNew().Hash(bytes.Join(inputs, nil), native.EllipticPointHasherSha256())
	// TODO: change hash to return an error also
	if err != nil {
		panic("cannot create Point from hash")
	}

	return &PointK256{value}
}

func (*PointK256) Identity() Point {
	return &PointK256{
		value: secp256k1.PointNew().Identity(),
	}
}

func (*PointK256) Generator() Point {
	return &PointK256{
		value: secp256k1.PointNew().Generator(),
	}
}

func (p *PointK256) IsIdentity() bool {
	return p.value.IsIdentity()
}

func (p *PointK256) IsNegative() bool {
	return p.value.GetY().Value[0]&1 == 1
}

func (p *PointK256) IsOnCurve() bool {
	return p.value.IsOnCurve()
}

func (p *PointK256) Double() Point {
	value := secp256k1.PointNew().Double(p.value)
	return &PointK256{value}
}

func (*PointK256) Scalar() Scalar {
	return new(ScalarK256).Zero()
}

func (p *PointK256) Neg() Point {
	value := secp256k1.PointNew().Neg(p.value)
	return &PointK256{value}
}

func (p *PointK256) Add(rhs Point) Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PointK256)
	if ok {
		value := secp256k1.PointNew().Add(p.value, r.value)
		return &PointK256{value}
	} else {
		panic("rhs is not PointK256")
	}
}

func (p *PointK256) Sub(rhs Point) Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PointK256)
	if ok {
		value := secp256k1.PointNew().Sub(p.value, r.value)
		return &PointK256{value}
	} else {
		panic("rhs is not PointK256")
	}
}

func (p *PointK256) Mul(rhs Scalar) Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*ScalarK256)
	if ok {
		value := secp256k1.PointNew().Mul(p.value, r.value)
		return &PointK256{value}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (p *PointK256) Equal(rhs Point) bool {
	r, ok := rhs.(*PointK256)
	if ok {
		return p.value.Equal(r.value) == 1
	} else {
		return false
	}
}

func (*PointK256) Set(x, y *big.Int) (Point, error) {
	value, err := secp256k1.PointNew().SetBigInt(x, y)
	if err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "could not set x,y")
	}
	return &PointK256{value}, nil
}

func (p *PointK256) ToAffineCompressed() []byte {
	var x [33]byte
	x[0] = byte(2)

	t := secp256k1.PointNew().ToAffine(p.value)

	x[0] |= t.Y.Bytes()[0] & 1

	xBytes := t.X.Bytes()
	copy(x[1:], bitstring.ReverseBytes(xBytes[:]))
	return x[:]
}

func (p *PointK256) ToAffineUncompressed() []byte {
	var out [65]byte
	out[0] = byte(4)
	t := secp256k1.PointNew().ToAffine(p.value)
	arr := t.X.Bytes()
	copy(out[1:33], bitstring.ReverseBytes(arr[:]))
	arr = t.Y.Bytes()
	copy(out[33:], bitstring.ReverseBytes(arr[:]))
	return out[:]
}

func (p *PointK256) FromAffineCompressed(input []byte) (Point, error) {
	var raw [native.FieldBytes]byte
	if len(input) != 33 {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	sign := int(input[0])
	if sign != 2 && sign != 3 {
		return nil, errs.NewFailed("invalid sign byte")
	}
	sign &= 0x1

	copy(raw[:], bitstring.ReverseBytes(input[1:]))
	x, err := fp.K256FpNew().SetBytes(&raw)
	if err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "x")
	}

	value := secp256k1.PointNew().Identity()
	rhs := fp.K256FpNew()
	p.value.Arithmetic.RhsEq(rhs, x)
	// test that rhs is quadratic residue
	// if not, then this Point is at infinity
	y, wasQr := fp.K256FpNew().Sqrt(rhs)
	if wasQr {
		// fix the sign
		sigY := int(y.Bytes()[0] & 1)
		if sigY != sign {
			y.Neg(y)
		}
		value.X = x
		value.Y = y
		value.Z.SetOne()
	}
	return &PointK256{value}, nil
}

func (*PointK256) FromAffineUncompressed(input []byte) (Point, error) {
	var arr [native.FieldBytes]byte
	if len(input) != 65 {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	if input[0] != 4 {
		return nil, errs.NewFailed("invalid sign byte")
	}

	copy(arr[:], bitstring.ReverseBytes(input[1:33]))
	x, err := fp.K256FpNew().SetBytes(&arr)
	if err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "x")
	}
	copy(arr[:], bitstring.ReverseBytes(input[33:]))
	y, err := fp.K256FpNew().SetBytes(&arr)
	if err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "y")
	}
	value := secp256k1.PointNew()
	value.X = x
	value.Y = y
	value.Z.SetOne()
	return &PointK256{value}, nil
}

func (p *PointK256) CurveName() string {
	return p.value.Params.Name
}

func multiScalarMultK256(scalars []Scalar, points []Point) (Point, error) {
	nPoints := make([]*native.EllipticPoint, len(points))
	nScalars := make([]*native.Field, len(scalars))
	for i, pt := range points {
		ptv, ok := pt.(*PointK256)
		if !ok {
			return nil, errs.NewFailed("invalid point type %s, expected PointK256", reflect.TypeOf(pt).Name())
		}
		nPoints[i] = ptv.value
	}
	for i, sc := range scalars {
		s, ok := sc.(*ScalarK256)
		if !ok {
			return nil, errs.NewFailed("invalid scalar type %s, expected ScalarK256", reflect.TypeOf(sc).Name())
		}
		nScalars[i] = s.value
	}
	value := secp256k1.PointNew()
	_, err := value.SumOfProducts(nPoints, nScalars)
	if err != nil {
		return nil, errs.WrapFailed(err, "multiscalar multiplication")
	}
	return &PointK256{value}, nil
}

func (p *PointK256) X() *native.Field {
	return p.value.GetX()
}

func (p *PointK256) Y() *native.Field {
	return p.value.GetY()
}

func (*PointK256) Params() *elliptic.CurveParams {
	return K256Curve().Params()
}

func (p *PointK256) MarshalBinary() ([]byte, error) {
	return pointMarshalBinary(p)
}

func (p *PointK256) UnmarshalBinary(input []byte) error {
	pt, err := pointUnmarshalBinary(input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*PointK256)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.value = ppt.value
	return nil
}

func (p *PointK256) MarshalText() ([]byte, error) {
	return pointMarshalText(p)
}

func (p *PointK256) UnmarshalText(input []byte) error {
	pt, err := pointUnmarshalText(input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*PointK256)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.value = ppt.value
	return nil
}

func (p *PointK256) MarshalJSON() ([]byte, error) {
	return pointMarshalJson(p)
}

func (p *PointK256) UnmarshalJSON(input []byte) error {
	curve, err := GetCurveByName(p.CurveName())
	if err != nil {
		return errs.WrapDeserializationFailed(err, "jon unmarshal failed")
	}
	pt, err := curve.NewPointFromJSON(input)
	if err != nil {
		return errs.WrapFailed(err, "could not extract a point from json")
	}
	P, ok := pt.(*PointK256)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.value = P.value
	return nil
}
