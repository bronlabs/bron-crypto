package p256

import (
	"bytes"
	"crypto/elliptic"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton/pkg/base/bitstring"
	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/curves/impl"
	"github.com/copperexchange/krypton/pkg/base/curves/internal"
	p256n "github.com/copperexchange/krypton/pkg/base/curves/p256/impl"
	"github.com/copperexchange/krypton/pkg/base/curves/p256/impl/fp"
	"github.com/copperexchange/krypton/pkg/base/errs"
	"github.com/copperexchange/krypton/pkg/base/types"
)

var _ curves.Point = (*Point)(nil)

type Point struct {
	Value *impl.EllipticPoint

	_ types.Incomparable
}

func (*Point) Curve() curves.Curve {
	return &p256Instance
}

func (p *Point) Random(reader io.Reader) curves.Point {
	var seed [64]byte
	_, _ = reader.Read(seed[:])
	return p.Hash(seed[:])
}

func (*Point) Hash(inputs ...[]byte) curves.Point {
	value, err := p256n.PointNew().Hash(bytes.Join(inputs, nil), impl.EllipticPointHasherSha256())
	// TODO: change hash to return an error also
	if err != nil {
		return nil
	}

	return &Point{Value: value}
}

func (*Point) Identity() curves.Point {
	return &Point{
		Value: p256n.PointNew().Identity(),
	}
}

func (*Point) Generator() curves.Point {
	return &Point{
		Value: p256n.PointNew().Generator(),
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
		Value: p256n.PointNew().Set(p.Value),
	}
}

func (p *Point) ClearCofactor() curves.Point {
	return p.Clone()
}

func (*Point) IsSmallOrder() bool {
	return false
}

func (p *Point) Double() curves.Point {
	value := p256n.PointNew().Double(p.Value)
	return &Point{Value: value}
}

func (*Point) Scalar() curves.Scalar {
	return new(Scalar).Zero()
}

func (p *Point) Neg() curves.Point {
	value := p256n.PointNew().Neg(p.Value)
	return &Point{Value: value}
}

func (p *Point) Add(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Point)
	if ok {
		value := p256n.PointNew().Add(p.Value, r.Value)
		return &Point{Value: value}
	} else {
		panic("rhs is not PointP256")
	}
}

func (p *Point) Sub(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Point)
	if ok {
		value := p256n.PointNew().Sub(p.Value, r.Value)
		return &Point{Value: value}
	} else {
		panic("rhs is not PointP256")
	}
}

func (p *Point) Mul(rhs curves.Scalar) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Scalar)
	if ok {
		value := p256n.PointNew().Mul(p.Value, r.Value)
		return &Point{Value: value}
	} else {
		panic("rhs is not ScalarP256")
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
	value, err := p256n.PointNew().SetNat(x, y)
	if err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "could not set x and y")
	}
	return &Point{Value: value}, nil
}

func (p *Point) ToAffineCompressed() []byte {
	var x [33]byte
	x[0] = byte(2)

	t := p256n.PointNew().ToAffine(p.Value)

	x[0] |= t.Y.Bytes()[0] & 1

	xBytes := t.X.Bytes()
	copy(x[1:], bitstring.ReverseBytes(xBytes[:]))
	return x[:]
}

func (p *Point) ToAffineUncompressed() []byte {
	var out [65]byte
	out[0] = byte(4)
	t := p256n.PointNew().ToAffine(p.Value)
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
		return nil, errs.NewSerializationError("invalid sign byte")
	}
	sign &= 0x1

	copy(raw[:], bitstring.ReverseBytes(input[1:]))
	x, err := fp.New().SetBytes(&raw)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "set bytes failed")
	}

	value := p256n.PointNew().Identity()
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
		return nil, errs.NewSerializationError("invalid sign byte")
	}

	copy(arr[:], bitstring.ReverseBytes(input[1:33]))
	x, err := fp.New().SetBytes(&arr)
	if err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "set bytes failed")
	}
	copy(arr[:], bitstring.ReverseBytes(input[33:]))
	y, err := fp.New().SetBytes(&arr)
	if err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "set bytes failed")
	}
	value := p256n.PointNew()
	value.X = x
	value.Y = y
	value.Z.SetOne()
	return &Point{Value: value}, nil
}

func (*Point) CurveName() string {
	return elliptic.P256().Params().Name
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

func (*Point) Params() *elliptic.CurveParams {
	return elliptic.P256().Params()
}

func (p *Point) MarshalBinary() ([]byte, error) {
	return internal.PointMarshalBinary(p)
}

func (p *Point) UnmarshalBinary(input []byte) error {
	pt, err := internal.PointUnmarshalBinary(&p256Instance, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ppt, ok := pt.(*Point)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *Point) MarshalText() ([]byte, error) {
	return internal.PointMarshalText(p)
}

func (p *Point) UnmarshalText(input []byte) error {
	pt, err := internal.PointUnmarshalText(&p256Instance, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ppt, ok := pt.(*Point)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *Point) MarshalJSON() ([]byte, error) {
	return internal.PointMarshalJson(p)
}

func (p *Point) UnmarshalJSON(input []byte) error {
	pt, err := internal.NewPointFromJSON(&p256Instance, input)
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
