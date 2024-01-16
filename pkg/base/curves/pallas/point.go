package pallas

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/serialisation"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

var _ curves.Point = (*Point)(nil)
var _ curves.JacobianCoordinates = (*Point)(nil)

type Point struct {
	V *Ep

	_ types.Incomparable
}

func NewPoint() *Point {
	return NewCurve().Identity().(*Point)
}

// === Basic Methods.

func (p *Point) Equal(rhs curves.Point) bool {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Point)
	if !ok {
		panic("rhs is not a pallas point")
	}
	return p.V.Equal(r.V)
}

func (p *Point) Clone() curves.Point {
	return &Point{V: new(Ep).Set(p.V)}
}

// === Groupoid Methods.

func (p *Point) Operate(rhs curves.Point) curves.Point {
	return p.Add(rhs)
}

func (p *Point) OperateIteratively(q curves.Point, n *saferith.Nat) curves.Point {
	return p.ApplyAdd(q, n)
}

func (p *Point) Order() *saferith.Modulus {
	if p.IsIdentity() {
		return saferith.ModulusFromUint64(0)
	}
	q := p.Clone()
	order := new(saferith.Nat).SetUint64(1)
	for !q.IsIdentity() {
		q = q.Add(p)
		utils.IncrementNat(order)
	}
	return saferith.ModulusFromNat(order)
}

// === Additive Groupoid Methods.

func (p *Point) Add(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Point)
	if !ok {
		panic("rhs is not a pallas point")
	}
	return &Point{V: new(Ep).Add(p.V, r.V)}
}

func (p *Point) ApplyAdd(q curves.Point, n *saferith.Nat) curves.Point {
	return p.Add(q.Mul(NewScalarField().Element().SetNat(n)))
}

func (p *Point) Double() curves.Point {
	return &Point{V: new(Ep).Double(p.V)}
}

func (p *Point) Triple() curves.Point {
	return p.Double().Add(p)
}

// === Monoid Methods.

func (p *Point) IsIdentity() bool {
	return p.V.IsIdentity()
}

// === Additive Monoid Methods.

func (p *Point) IsAdditiveIdentity() bool {
	return p.IsIdentity()
}

// === Group Methods.

func (p *Point) Inverse() curves.Point {
	return &Point{V: new(Ep).Neg(p.V)}
}

func (p *Point) IsInverse(of curves.Point) bool {
	return p.Operate(of).IsIdentity()
}

// === Additive Group Methods.

func (p *Point) AdditiveInverse() curves.Point {
	return p.Inverse()
}

func (p *Point) IsAdditiveInverse(of curves.Point) bool {
	return p.IsInverse(of)
}

func (p *Point) Sub(rhs curves.Point) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	r, ok := rhs.(*Point)
	if !ok {
		panic("rhs is not a pallas point")
	}
	return &Point{V: new(Ep).Sub(p.V, r.V)}
}

func (p *Point) ApplySub(q curves.Point, n *saferith.Nat) curves.Point {
	return p.Sub(q.Mul(NewScalarField().Element().SetNat(n)))
}

// === Vector Space Methods.

func (p *Point) Mul(rhs curves.Scalar) curves.Point {
	if rhs == nil {
		panic("rhs is nil")
	}
	s, ok := rhs.(*Scalar)
	if !ok {
		panic("rhs is not a pallas point")
	}
	return &Point{V: new(Ep).Mul(p.V, s.V)}
}

// === Curve Methods.

func (*Point) Curve() curves.Curve {
	return &pallasInstance
}

func (p *Point) Neg() curves.Point {
	return p.Inverse()
}

func (p *Point) IsNegative() bool {
	return p.V.GetY().IsOdd()
}

func (*Point) IsSmallOrder() bool {
	return false
}

func (p *Point) IsTorsionElement(order *saferith.Modulus) bool {
	e := p.Curve().ScalarField().Element().SetNat(order.Nat())
	return p.Mul(e).IsIdentity()
}

func (p *Point) ClearCofactor() curves.Point {
	return p.Clone()
}

// === Coordinates interface methods.

func (p *Point) AffineCoordinates() []curves.BaseFieldElement {
	return []curves.BaseFieldElement{p.AffineX(), p.AffineY()}
}

func (p *Point) AffineX() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: p.V.GetX(),
	}
}

func (p *Point) AffineY() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: p.V.GetY(),
	}
}

func (p *Point) JacobianX() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: p.V.X,
	}
}

func (p *Point) JacobianY() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: p.V.Y,
	}
}

func (p *Point) JacobianZ() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: p.V.Z,
	}
}

// === Serialisation.

func (p *Point) ToAffineCompressed() []byte {
	return p.V.ToAffineCompressed()
}

func (p *Point) ToAffineUncompressed() []byte {
	return p.V.ToAffineUncompressed()
}

func (*Point) FromAffineCompressed(input []byte) (curves.Point, error) {
	value, err := new(Ep).FromAffineCompressed(input)
	if err != nil {
		return nil, err
	}
	return &Point{V: value}, nil
}

func (*Point) FromAffineUncompressed(input []byte) (curves.Point, error) {
	value, err := new(Ep).FromAffineUncompressed(input)
	if err != nil {
		return nil, err
	}
	return &Point{V: value}, nil
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
	p.V = ppt.V
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
	p.V = P.V
	return nil
}

// === Misc.

func (p *Point) GetEp() *Ep {
	return new(Ep).Set(p.V)
}
