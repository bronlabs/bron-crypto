package k256

import (
	"bytes"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/internal"
	secp256k1 "github.com/copperexchange/knox-primitives/pkg/core/curves/k256/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256/impl/fp"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var _ curves.Point = (*PointK256)(nil)

type PointK256 struct {
	Value *impl.EllipticPoint

	_ helper_types.Incomparable
}

func (*PointK256) Curve() curves.Curve {
	return &k256Instance
}

func (p *PointK256) Random(prng io.Reader) curves.Point {
	var seed [64]byte
	_, _ = prng.Read(seed[:])
	return p.Hash(seed[:])
}

func (*PointK256) Hash(inputs ...[]byte) curves.Point {
	value, err := secp256k1.PointNew().Hash(bytes.Join(inputs, nil), impl.EllipticPointHasherSha256())
	// TODO: change hash to return an error also
	if err != nil {
		panic("cannot create Point from hash")
	}

	return &PointK256{Value: value}
}

func (*PointK256) Identity() curves.Point {
	return &PointK256{
		Value: secp256k1.PointNew().Identity(),
	}
}

func (*PointK256) Generator() curves.Point {
	return &PointK256{
		Value: secp256k1.PointNew().Generator(),
	}
}

func (p *PointK256) IsIdentity() bool {
	return p.Value.IsIdentity()
}

func (p *PointK256) IsNegative() bool {
	return p.Value.GetY().Value[0]&1 == 1
}

func (p *PointK256) IsOnCurve() bool {
	return p.Value.IsOnCurve()
}

func (p *PointK256) Clone() curves.Point {
	return &PointK256{
		Value: secp256k1.PointNew().Set(p.Value),
	}
}

func (p *PointK256) ClearCofactor() curves.Point {
	return p.Clone()
}

func (p *PointK256) Double() curves.Point {
	value := secp256k1.PointNew().Double(p.Value)
	return &PointK256{Value: value}
}

func (*PointK256) Scalar() curves.Scalar {
	return new(ScalarK256).Zero()
}

func (p *PointK256) Neg() curves.Point {
	value := secp256k1.PointNew().Neg(p.Value)
	return &PointK256{Value: value}
}

func (p *PointK256) Add(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PointK256)
	if ok {
		value := secp256k1.PointNew().Add(p.Value, r.Value)
		return &PointK256{Value: value}
	} else {
		panic("rhs is not PointK256")
	}
}

func (p *PointK256) Sub(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PointK256)
	if ok {
		value := secp256k1.PointNew().Sub(p.Value, r.Value)
		return &PointK256{Value: value}
	} else {
		panic("rhs is not PointK256")
	}
}

func (p *PointK256) Mul(rhs curves.Scalar) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*ScalarK256)
	if ok {
		value := secp256k1.PointNew().Mul(p.Value, r.Value)
		return &PointK256{Value: value}
	} else {
		panic("rhs is not ScalarK256")
	}
}

func (p *PointK256) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*PointK256)
	if ok {
		return p.Value.Equal(r.Value) == 1
	} else {
		return false
	}
}

func (*PointK256) Set(x, y *saferith.Nat) (curves.Point, error) {
	value, err := secp256k1.PointNew().SetNat(x, y)
	if err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "could not set x,y")
	}
	return &PointK256{Value: value}, nil
}

func (p *PointK256) ToAffineCompressed() []byte {
	var x [33]byte
	x[0] = byte(2)

	t := secp256k1.PointNew().ToAffine(p.Value)

	x[0] |= t.Y.Bytes()[0] & 1

	xBytes := t.X.Bytes()
	copy(x[1:], bitstring.ReverseBytes(xBytes[:]))
	return x[:]
}

func (p *PointK256) ToAffineUncompressed() []byte {
	var out [65]byte
	out[0] = byte(4)
	t := secp256k1.PointNew().ToAffine(p.Value)
	arr := t.X.Bytes()
	copy(out[1:33], bitstring.ReverseBytes(arr[:]))
	arr = t.Y.Bytes()
	copy(out[33:], bitstring.ReverseBytes(arr[:]))
	return out[:]
}

func (p *PointK256) FromAffineCompressed(input []byte) (curves.Point, error) {
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
	return &PointK256{Value: value}, nil
}

func (*PointK256) FromAffineUncompressed(input []byte) (curves.Point, error) {
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
	return &PointK256{Value: value}, nil
}

func (p *PointK256) CurveName() string {
	return p.Value.Params.Name
}

func (p *PointK256) X() curves.FieldElement {
	return &FieldElementK256{
		v: p.Value.GetX(),
	}
}

func (p *PointK256) Y() curves.FieldElement {
	return &FieldElementK256{
		v: p.Value.GetY(),
	}
}

func (p *PointK256) ProjectiveX() curves.FieldElement {
	return &FieldElementK256{
		v: p.Value.X,
	}
}

func (p *PointK256) ProjectiveY() curves.FieldElement {
	return &FieldElementK256{
		v: p.Value.Y,
	}
}

func (p *PointK256) ProjectiveZ() curves.FieldElement {
	return &FieldElementK256{
		v: p.Value.Z,
	}
}

func (p *PointK256) MarshalBinary() ([]byte, error) {
	return internal.PointMarshalBinary(p)
}

func (p *PointK256) UnmarshalBinary(input []byte) error {
	pt, err := internal.PointUnmarshalBinary(&k256Instance, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal binary")
	}
	ppt, ok := pt.(*PointK256)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *PointK256) MarshalText() ([]byte, error) {
	return internal.PointMarshalText(p)
}

func (p *PointK256) UnmarshalText(input []byte) error {
	pt, err := internal.PointUnmarshalText(&k256Instance, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal text")
	}
	ppt, ok := pt.(*PointK256)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *PointK256) MarshalJSON() ([]byte, error) {
	return internal.PointMarshalJson(p)
}

func (p *PointK256) UnmarshalJSON(input []byte) error {
	pt, err := internal.NewPointFromJSON(&k256Instance, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	P, ok := pt.(*PointK256)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.Value = P.Value
	return nil
}
