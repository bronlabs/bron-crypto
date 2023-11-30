package k256

import (
	"bytes"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	secp256k1 "github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl/fp"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/serialisation"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ curves.Point[CurveIdentifierK256] = (*PointK256)(nil)

type PointK256 struct {
	Value *impl.EllipticPoint

	_ types.Incomparable
}

func NewPoint() curves.Point[CurveIdentifierK256] {
	emptyPoint := &PointK256{}
	result, _ := emptyPoint.Identity().(*PointK256)
	return result
}

func (PointK256) Curve() curves.Curve[CurveIdentifierK256] {
	return New()
}

func (p PointK256) Random(prng io.Reader) (curves.Point[CurveIdentifierK256], error) {
	var seed [64]byte
	_, _ = prng.Read(seed[:])
	return p.Hash(seed[:])
}

func (PointK256) Hash(inputs ...[]byte) (curves.Point[CurveIdentifierK256], error) {
	p := secp256k1.PointNew()
	u, err := New().HashToFieldElements(2, bytes.Join(inputs, nil), nil)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "hash to field element of K256 failed")
	}
	u0, ok0 := u[0].(*FieldElementK256)
	u1, ok1 := u[1].(*FieldElementK256)
	if !ok0 || !ok1 {
		return nil, errs.NewHashingFailed("Cast to K256 field elements failed")
	}
	err = p.Arithmetic.Map(u0.v, u1.v, p)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "Map to K256 point failed")
	}
	return &PointK256{Value: p}, nil
}

func (PointK256) Identity() curves.Point[CurveIdentifierK256] {
	return &PointK256{
		Value: secp256k1.PointNew().Identity(),
	}
}

func (PointK256) Generator() curves.Point[CurveIdentifierK256] {
	return &PointK256{
		Value: secp256k1.PointNew().Generator(),
	}
}

func (p PointK256) IsIdentity() bool {
	return p.Value.IsIdentity()
}

func (p PointK256) IsNegative() bool {
	return p.Value.GetY().Value[0]&1 == 1
}

func (p PointK256) IsOnCurve() bool {
	return p.Value.IsOnCurve()
}

func (p PointK256) Clone() curves.Point[CurveIdentifierK256] {
	return &PointK256{
		Value: secp256k1.PointNew().Set(p.Value),
	}
}

func (p PointK256) ClearCofactor() curves.Point[CurveIdentifierK256] {
	return p.Clone()
}

func (PointK256) IsSmallOrder() bool {
	return false
}

func (p PointK256) Double() curves.Point[CurveIdentifierK256] {
	value := secp256k1.PointNew().Double(p.Value)
	return &PointK256{Value: value}
}

func (PointK256) Scalar() curves.Scalar[CurveIdentifierK256] {
	return new(ScalarK256).Zero()
}

func (p PointK256) Neg() curves.Point[CurveIdentifierK256] {
	value := secp256k1.PointNew().Neg(p.Value)
	return &PointK256{Value: value}
}

func (p PointK256) Add(rhs curves.Point[CurveIdentifierK256]) curves.Point[CurveIdentifierK256] {
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

func (p PointK256) Sub(rhs curves.Point[CurveIdentifierK256]) curves.Point[CurveIdentifierK256] {
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

func (p PointK256) Mul(rhs curves.Scalar[CurveIdentifierK256]) curves.Point[CurveIdentifierK256] {
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

func (p PointK256) Equal(rhs curves.Point[CurveIdentifierK256]) bool {
	r, ok := rhs.(*PointK256)
	if ok {
		return p.Value.Equal(r.Value) == 1
	} else {
		return false
	}
}

func (PointK256) Set(x, y *saferith.Nat) (curves.Point[CurveIdentifierK256], error) {
	value, err := secp256k1.PointNew().SetNat(x, y)
	if err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "could not set x,y")
	}
	return &PointK256{Value: value}, nil
}

func (p PointK256) ToAffineCompressed() []byte {
	var x [33]byte
	x[0] = byte(2)

	t := secp256k1.PointNew().ToAffine(p.Value)

	x[0] |= t.Y.Bytes()[0] & 1

	xBytes := t.X.Bytes()
	copy(x[1:], bitstring.ReverseBytes(xBytes[:]))
	return x[:]
}

func (p PointK256) ToAffineUncompressed() []byte {
	var out [65]byte
	out[0] = byte(4)
	t := secp256k1.PointNew().ToAffine(p.Value)
	arr := t.X.Bytes()
	copy(out[1:33], bitstring.ReverseBytes(arr[:]))
	arr = t.Y.Bytes()
	copy(out[33:], bitstring.ReverseBytes(arr[:]))
	return out[:]
}

func (p PointK256) FromAffineCompressed(input []byte) (curves.Point[CurveIdentifierK256], error) {
	var raw [base.FieldBytes]byte
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
	// if not, then this PointK256 is at infinity
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

func (PointK256) FromAffineUncompressed(input []byte) (curves.Point[CurveIdentifierK256], error) {
	var arr [base.FieldBytes]byte
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

func (PointK256) CurveName() string {
	return Name
}

func (p PointK256) X() curves.FieldElement[CurveIdentifierK256] {
	return &FieldElementK256{
		v: p.Value.GetX(),
	}
}

func (p PointK256) Y() curves.FieldElement[CurveIdentifierK256] {
	return &FieldElementK256{
		v: p.Value.GetY(),
	}
}

func (p PointK256) ProjectiveX() curves.FieldElement[CurveIdentifierK256] {
	return &FieldElementK256{
		v: p.Value.X,
	}
}

func (p PointK256) ProjectiveY() curves.FieldElement[CurveIdentifierK256] {
	return &FieldElementK256{
		v: p.Value.Y,
	}
}

func (p PointK256) ProjectiveZ() curves.FieldElement[CurveIdentifierK256] {
	return &FieldElementK256{
		v: p.Value.Z,
	}
}

func (p PointK256) MarshalBinary() ([]byte, error) {
	res, err := serialisation.PointMarshalBinary(p.Clone())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "Could not marshal point to binary")
	}
	return res, nil
}

func (p PointK256) UnmarshalBinary(input []byte) error {
	pt, err := serialisation.PointUnmarshalBinary(New(), input)
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

func (p PointK256) MarshalText() ([]byte, error) {
	res, err := serialisation.PointMarshalText(p.Clone())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "Could not marshal point to text")
	}
	return res, nil
}

func (p PointK256) UnmarshalText(input []byte) error {
	pt, err := serialisation.PointUnmarshalText(New(), input)
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

func (p PointK256) MarshalJSON() ([]byte, error) {
	res, err := serialisation.PointMarshalJson(p.Clone())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "Could not marshal point to json")
	}
	return res, nil
}

func (p PointK256) UnmarshalJSON(input []byte) error {
	pt, err := serialisation.NewPointFromJSON(New(), input)
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
