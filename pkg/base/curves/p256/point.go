package p256

import (
	"bytes"
	"crypto/elliptic"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	p256n "github.com/copperexchange/krypton-primitives/pkg/base/curves/p256/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256/impl/fp"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/serialisation"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ curves.Point[CurveIdentifierP256] = (*PointP256)(nil)

type PointP256 struct {
	Value *impl.EllipticPoint

	_ types.Incomparable
}

func NewPoint() *PointP256 {
	emptyPoint := &PointP256{}
	result, _ := emptyPoint.Identity().(*PointP256)
	return result
}

func (*PointP256) Curve() curves.Curve[CurveIdentifierP256] {
	return &p256Instance
}

func (p *PointP256) Random(reader io.Reader) (curves.Point[CurveIdentifierP256], error) {
	var seed [base.WideFieldBytes]byte
	_, _ = reader.Read(seed[:])
	return p.Hash(seed[:])
}

func (*PointP256) Hash(inputs ...[]byte) (curves.Point[CurveIdentifierP256], error) {
	p := p256n.PointNew()
	u, err := New().HashToFieldElements(2, bytes.Join(inputs, nil), nil)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "hash to field element of P256 failed")
	}
	u0, ok0 := u[0].(*FieldElementP256)
	u1, ok1 := u[1].(*FieldElementP256)
	if !ok0 || !ok1 {
		return nil, errs.NewHashingFailed("cast to P256 field element failed")
	}
	err = p.Arithmetic.Map(u0.v, u1.v, p)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "map to P256 point failed")
	}
	return &PointP256{Value: p}, nil
}

func (*PointP256) Identity() curves.Point[CurveIdentifierP256] {
	return &PointP256{
		Value: p256n.PointNew().Identity(),
	}
}

func (*PointP256) Generator() curves.Point[CurveIdentifierP256] {
	return &PointP256{
		Value: p256n.PointNew().Generator(),
	}
}

func (p *PointP256) IsIdentity() bool {
	return p.Value.IsIdentity()
}

func (p *PointP256) IsNegative() bool {
	return p.Value.GetY().Value[0]&1 == 1
}

func (p *PointP256) IsOnCurve() bool {
	return p.Value.IsOnCurve()
}

func (p *PointP256) Clone() curves.Point[CurveIdentifierP256] {
	return &PointP256{
		Value: p256n.PointNew().Set(p.Value),
	}
}

func (p *PointP256) ClearCofactor() curves.Point[CurveIdentifierP256] {
	return p.Clone()
}

func (*PointP256) IsSmallOrder() bool {
	return false
}

func (p *PointP256) Double() curves.Point[CurveIdentifierP256] {
	value := p256n.PointNew().Double(p.Value)
	return &PointP256{Value: value}
}

func (*PointP256) Scalar() curves.Scalar[CurveIdentifierP256] {
	return new(ScalarP256).Zero()
}

func (p *PointP256) Neg() curves.Point[CurveIdentifierP256] {
	value := p256n.PointNew().Neg(p.Value)
	return &PointP256{Value: value}
}

func (p *PointP256) Add(rhs curves.Point[CurveIdentifierP256]) curves.Point[CurveIdentifierP256] {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PointP256)
	if ok {
		value := p256n.PointNew().Add(p.Value, r.Value)
		return &PointP256{Value: value}
	} else {
		panic("rhs is not PointP256")
	}
}

func (p *PointP256) Sub(rhs curves.Point[CurveIdentifierP256]) curves.Point[CurveIdentifierP256] {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*PointP256)
	if ok {
		value := p256n.PointNew().Sub(p.Value, r.Value)
		return &PointP256{Value: value}
	} else {
		panic("rhs is not PointP256")
	}
}

func (p *PointP256) Mul(rhs curves.Scalar[CurveIdentifierP256]) curves.Point[CurveIdentifierP256] {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*ScalarP256)
	if ok {
		value := p256n.PointNew().Mul(p.Value, r.Value)
		return &PointP256{Value: value}
	} else {
		panic("rhs is not ScalarP256")
	}
}

func (p *PointP256) Equal(rhs curves.Point[CurveIdentifierP256]) bool {
	r, ok := rhs.(*PointP256)
	if ok {
		return p.Value.Equal(r.Value) == 1
	} else {
		return false
	}
}

func (*PointP256) Set(x, y *saferith.Nat) (curves.Point[CurveIdentifierP256], error) {
	value, err := p256n.PointNew().SetNat(x, y)
	if err != nil {
		return nil, errs.WrapInvalidCoordinates(err, "could not set x and y")
	}
	return &PointP256{Value: value}, nil
}

func (p *PointP256) ToAffineCompressed() []byte {
	var x [33]byte
	x[0] = byte(2)

	t := p256n.PointNew().ToAffine(p.Value)

	x[0] |= t.Y.Bytes()[0] & 1

	xBytes := t.X.Bytes()
	copy(x[1:], bitstring.ReverseBytes(xBytes[:]))
	return x[:]
}

func (p *PointP256) ToAffineUncompressed() []byte {
	var out [65]byte
	out[0] = byte(4)
	t := p256n.PointNew().ToAffine(p.Value)
	arr := t.X.Bytes()
	copy(out[1:33], bitstring.ReverseBytes(arr[:]))
	arr = t.Y.Bytes()
	copy(out[33:], bitstring.ReverseBytes(arr[:]))
	return out[:]
}

func (p *PointP256) FromAffineCompressed(input []byte) (curves.Point[CurveIdentifierP256], error) {
	var raw [base.FieldBytes]byte
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
	// if not, then this PointP256 is at infinity
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
	return &PointP256{Value: value}, nil
}

func (*PointP256) FromAffineUncompressed(input []byte) (curves.Point[CurveIdentifierP256], error) {
	var arr [base.FieldBytes]byte
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
	return &PointP256{Value: value}, nil
}

func (*PointP256) CurveName() string {
	return Name
}

func (p *PointP256) X() curves.FieldElement[CurveIdentifierP256] {
	return &FieldElementP256{
		v: p.Value.GetX(),
	}
}

func (p *PointP256) Y() curves.FieldElement[CurveIdentifierP256] {
	return &FieldElementP256{
		v: p.Value.GetY(),
	}
}

func (p *PointP256) ProjectiveX() curves.FieldElement[CurveIdentifierP256] {
	return &FieldElementP256{
		v: p.Value.X,
	}
}

func (p *PointP256) ProjectiveY() curves.FieldElement[CurveIdentifierP256] {
	return &FieldElementP256{
		v: p.Value.Y,
	}
}

func (p *PointP256) ProjectiveZ() curves.FieldElement[CurveIdentifierP256] {
	return &FieldElementP256{
		v: p.Value.Z,
	}
}

func (*PointP256) Params() *elliptic.CurveParams {
	return elliptic.P256().Params()
}

func (p *PointP256) MarshalBinary() ([]byte, error) {
	res, err := serialisation.PointMarshalBinary(p.Clone())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not marshal")
	}
	return res, nil
}

func (p *PointP256) UnmarshalBinary(input []byte) error {
	pt, err := serialisation.PointUnmarshalBinary(New(), input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ppt, ok := pt.(*PointP256)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *PointP256) MarshalText() ([]byte, error) {
	res, err := serialisation.PointMarshalText(p.Clone())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not marshal")
	}
	return res, nil
}

func (p *PointP256) UnmarshalText(input []byte) error {
	pt, err := serialisation.PointUnmarshalText(New(), input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ppt, ok := pt.(*PointP256)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.Value = ppt.Value
	return nil
}

func (p *PointP256) MarshalJSON() ([]byte, error) {
	res, err := serialisation.PointMarshalJson(p.Clone())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not marshal")
	}
	return res, nil
}

func (p *PointP256) UnmarshalJSON(input []byte) error {
	pt, err := serialisation.NewPointFromJSON(New(), input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	P, ok := pt.(*PointP256)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.Value = P.Value
	return nil
}
