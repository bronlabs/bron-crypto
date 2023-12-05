package pallas

import (
	"bytes"
	"crypto/subtle"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas/impl/fp"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas/impl/fq"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/serialisation"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ curves.Point = (*Point)(nil)

type Point struct {
	Value *Ep

	_ types.Incomparable
}

func NewPoint() *Point {
	emptyPoint := &Point{}
	result, _ := emptyPoint.Identity().(*Point)
	return result
}

func (*Point) Curve() curves.Curve {
	return &pallasInstance
}

func (*Point) CurveName() string {
	return Name
}

func (p *Point) Random(reader io.Reader) (curves.Point, error) {
	var seed [base.WideFieldBytes]byte
	_, _ = reader.Read(seed[:])
	return p.Hash(seed[:])
}

func (*Point) Hash(inputs ...[]byte) (curves.Point, error) {
	p := new(Ep)
	u, err := New().HashToFieldElements(2, bytes.Join(inputs, nil), nil)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "hash to field element of P256 failed")
	}
	u0, ok0 := u[0].(*FieldElement)
	u1, ok1 := u[1].(*FieldElement)
	if !ok0 || !ok1 {
		return nil, errs.NewHashingFailed("cast to P256 field element failed")
	}
	p = p.Map(u0.v, u1.v)
	return &Point{Value: p}, nil
}

func (*Point) Identity() curves.Point {
	return &Point{Value: new(Ep).Identity()}
}

func (*Point) Generator() curves.Point {
	return &Point{Value: new(Ep).Generator()}
}

func (p *Point) Clone() curves.Point {
	return &Point{Value: new(Ep).Set(p.Value)}
}

func (p *Point) ClearCofactor() curves.Point {
	return p.Clone()
}

func (*Point) IsSmallOrder() bool {
	return false
}

func (p *Point) IsIdentity() bool {
	return p.Value.IsIdentity()
}

func (p *Point) IsNegative() bool {
	return p.Value.GetY().IsOdd()
}

func (p *Point) IsOnCurve() bool {
	return p.Value.IsOnCurve()
}

func (p *Point) Double() curves.Point {
	return &Point{Value: new(Ep).Double(p.Value)}
}

func (*Point) Scalar() curves.Scalar {
	return &Scalar{Value: new(fq.Fq).SetZero()}
}

func (p *Point) Neg() curves.Point {
	return &Point{Value: new(Ep).Neg(p.Value)}
}

func (p *Point) Add(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Point)
	if !ok {
		panic("rhs is not a pallas point")
	}
	return &Point{Value: new(Ep).Add(p.Value, r.Value)}
}

func (p *Point) Sub(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Point)
	if !ok {
		panic("rhs is not a pallas point")
	}
	return &Point{Value: new(Ep).Sub(p.Value, r.Value)}
}

func (p *Point) Mul(rhs curves.Scalar) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	s, ok := rhs.(*Scalar)
	if !ok {
		panic("rhs is not a pallas point")
	}
	return &Point{Value: new(Ep).Mul(p.Value, s.Value)}
}

func (p *Point) Equal(rhs curves.Point) bool {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Point)
	if !ok {
		panic("rhs is not a pallas point")
	}
	return p.Value.Equal(r.Value)
}

func (p *Point) Set(x, y *saferith.Nat) (curves.Point, error) {
	xx := subtle.ConstantTimeCompare(x.Bytes(), []byte{})
	yy := subtle.ConstantTimeCompare(y.Bytes(), []byte{})
	xElem := new(fp.Fp).SetNat(x)
	var data [32]byte
	if yy == 1 {
		if xx == 1 {
			return &Point{Value: new(Ep).Identity()}, nil
		}
		data = xElem.Bytes()
		return p.FromAffineCompressed(data[:])
	}
	yElem := new(fp.Fp).SetNat(y)
	value := &Ep{X: xElem, Y: yElem, Z: new(fp.Fp).SetOne()}
	if !value.IsOnCurve() {
		return nil, errs.NewMembership("point is not on the curve")
	}
	return &Point{Value: value}, nil
}

func (p *Point) ToAffineCompressed() []byte {
	return p.Value.ToAffineCompressed()
}

func (p *Point) ToAffineUncompressed() []byte {
	return p.Value.ToAffineUncompressed()
}

func (*Point) FromAffineCompressed(input []byte) (curves.Point, error) {
	value, err := new(Ep).FromAffineCompressed(input)
	if err != nil {
		return nil, err
	}
	return &Point{Value: value}, nil
}

func (*Point) FromAffineUncompressed(input []byte) (curves.Point, error) {
	value, err := new(Ep).FromAffineUncompressed(input)
	if err != nil {
		return nil, err
	}
	return &Point{Value: value}, nil
}

func (p *Point) MarshalBinary() ([]byte, error) {
	res, err := serialisation.PointMarshalBinary(p)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (p *Point) UnmarshalBinary(input []byte) error {
	pt, err := serialisation.PointUnmarshalBinary(&pallasInstance, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
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
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (p *Point) UnmarshalText(input []byte) error {
	pt, err := serialisation.PointUnmarshalText(&pallasInstance, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
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
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (p *Point) UnmarshalJSON(input []byte) error {
	pt, err := serialisation.NewPointFromJSON(&pallasInstance, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
	}
	P, ok := pt.(*Point)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.Value = P.Value
	return nil
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

func (p *Point) JacobianX() curves.FieldElement {
	return &FieldElement{
		v: p.Value.X,
	}
}

func (p *Point) JacobianY() curves.FieldElement {
	return &FieldElement{
		v: p.Value.Y,
	}
}

func (p *Point) Jacobian() curves.FieldElement {
	return &FieldElement{
		v: p.Value.Z,
	}
}

func (p *Point) GetEp() *Ep {
	return new(Ep).Set(p.Value)
}
