package k256

import (
	"bytes"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	secp256k1 "github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl/fp"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/serialisation"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/hashing/hash2curve"
)

var _ curves.Point = (*Point)(nil)

type Point struct {
	Value *impl.EllipticPoint

	_ types.Incomparable
}

func (*Point) Curve() curves.Curve {
	return &k256Instance
}

func (p *Point) Random(prng io.Reader) curves.Point {
	var seed [64]byte
	_, _ = prng.Read(seed[:])
	return p.Hash(seed[:])
}

func (*Point) Hash(inputs ...[]byte) curves.Point {
	value, err := secp256k1.PointNew().Hash(bytes.Join(inputs, nil), hash2curve.EllipticCurveHasherSha256())
	// TODO: change hash to return an error also
	if err != nil {
		panic(err)
	}

	return &Point{Value: value}
}

func (*Point) Identity() curves.Point {
	return &Point{
		Value: secp256k1.PointNew().Identity(),
	}
}

func (*Point) Generator() curves.Point {
	return &Point{
		Value: secp256k1.PointNew().Generator(),
	}
}

func (p *Point) IsIdentity() bool {
	return p.Value.IsIdentity()
}

func (p *Point) IsNegative() bool {
	return p.Value.GetY().Value[0]&1 == 1
}

func (p *Point) IsOnCurve() bool {
	return p.Value.IsOnCurve()
}

func (p *Point) Clone() curves.Point {
	return &Point{
		Value: secp256k1.PointNew().Set(p.Value),
	}
}

func (p *Point) ClearCofactor() curves.Point {
	return p.Clone()
}

func (*Point) IsSmallOrder() bool {
	return false
}

func (p *Point) Double() curves.Point {
	value := secp256k1.PointNew().Double(p.Value)
	return &Point{Value: value}
}

func (*Point) Scalar() curves.Scalar {
	return new(Scalar).Zero()
}

func (p *Point) Neg() curves.Point {
	value := secp256k1.PointNew().Neg(p.Value)
	return &Point{Value: value}
}

func (p *Point) Add(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Point)
	if ok {
		value := secp256k1.PointNew().Add(p.Value, r.Value)
		return &Point{Value: value}
	} else {
		panic("rhs is not PointK256")
	}
}

func (p *Point) Sub(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Point)
	if ok {
		value := secp256k1.PointNew().Sub(p.Value, r.Value)
		return &Point{Value: value}
	} else {
		panic("rhs is not PointK256")
	}
}

func (p *Point) Mul(rhs curves.Scalar) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Scalar)
	if ok {
		value := secp256k1.PointNew().Mul(p.Value, r.Value)
		return &Point{Value: value}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (p *Point) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*Point)
	if ok {
		return p.Value.Equal(r.Value) == 1
	} else {
		return false
	}
}

func (*Point) Set(x, y *saferith.Nat) (curves.Point, error) {
	value, err := secp256k1.PointNew().SetNat(x, y)
	if err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "could not set x,y")
	}
	return &Point{Value: value}, nil
}

func (p *Point) ToAffineCompressed() []byte {
	var x [33]byte
	x[0] = byte(2)

	t := secp256k1.PointNew().ToAffine(p.Value)

	x[0] |= t.Y.Bytes()[0] & 1

	xBytes := t.X.Bytes()
	copy(x[1:], bitstring.ReverseBytes(xBytes[:]))
	return x[:]
}

func (p *Point) ToAffineUncompressed() []byte {
	var out [65]byte
	out[0] = byte(4)
	t := secp256k1.PointNew().ToAffine(p.Value)
	arr := t.X.Bytes()
	copy(out[1:33], bitstring.ReverseBytes(arr[:]))
	arr = t.Y.Bytes()
	copy(out[33:], bitstring.ReverseBytes(arr[:]))
	return out[:]
}

func (p *Point) FromAffineCompressed(input []byte) (curves.Point, error) {
	var raw [impl.FieldBytes]byte
	if len(input) != 33 {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	sign := int(input[0])
	if sign != 2 && sign != 3 {
		return nil, errs.NewFailed("invalid sign byte")
	}
	sign &= 0x1

	copy(raw[:], bitstring.ReverseBytes(input[1:]))
	x, err := fp.New().SetBytes(&raw)
	if err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "x")
	}

	value := secp256k1.PointNew().Identity()
	rhs := fp.New()
	p.Value.Arithmetic.RhsEq(rhs, x)
	// test that rhs is quadratic residue
	// if not, then this Point is at infinity
	y, wasQr := fp.New().Sqrt(rhs)
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
	return &Point{Value: value}, nil
}

func (*Point) FromAffineUncompressed(input []byte) (curves.Point, error) {
	var arr [impl.FieldBytes]byte
	if len(input) != 65 {
		return nil, errs.NewInvalidLength("invalid byte sequence")
	}
	if input[0] != 4 {
		return nil, errs.NewFailed("invalid sign byte")
	}

	copy(arr[:], bitstring.ReverseBytes(input[1:33]))
	x, err := fp.New().SetBytes(&arr)
	if err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "x")
	}
	copy(arr[:], bitstring.ReverseBytes(input[33:]))
	y, err := fp.New().SetBytes(&arr)
	if err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "y")
	}
	value := secp256k1.PointNew()
	value.X = x
	value.Y = y
	value.Z.SetOne()
	return &Point{Value: value}, nil
}

func (p *Point) CurveName() string {
	return p.Value.Params.Name
}

func (p *Point) X() curves.FieldElement {
	return &FieldElement{
		v: p.Value.GetX(),
	}
}

func (p *Point) Y() curves.FieldElement {
	return &FieldElement{
		v: p.Value.GetY(),
	}
}

func (p *Point) ProjectiveX() curves.FieldElement {
	return &FieldElement{
		v: p.Value.X,
	}
}

func (p *Point) ProjectiveY() curves.FieldElement {
	return &FieldElement{
		v: p.Value.Y,
	}
}

func (p *Point) ProjectiveZ() curves.FieldElement {
	return &FieldElement{
		v: p.Value.Z,
	}
}

func (p *Point) MarshalBinary() ([]byte, error) {
	res, err := serialisation.PointMarshalBinary(p)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "Could not marshal point to binary")
	}
	return res, nil
}

func (p *Point) UnmarshalBinary(input []byte) error {
	pt, err := serialisation.PointUnmarshalBinary(&k256Instance, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal binary")
	}
	ppt, ok := pt.(*Point)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *Point) MarshalText() ([]byte, error) {
	res, err := serialisation.PointMarshalText(p)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "Could not marshal point to text")
	}
	return res, nil
}

func (p *Point) UnmarshalText(input []byte) error {
	pt, err := serialisation.PointUnmarshalText(&k256Instance, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal text")
	}
	ppt, ok := pt.(*Point)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *Point) MarshalJSON() ([]byte, error) {
	res, err := serialisation.PointMarshalJson(p)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "Could not marshal point to json")
	}
	return res, nil
}

func (p *Point) UnmarshalJSON(input []byte) error {
	pt, err := serialisation.NewPointFromJSON(&k256Instance, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	P, ok := pt.(*Point)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.Value = P.Value
	return nil
}
