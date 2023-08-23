package pallas

import (
	"bytes"
	"crypto/subtle"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/pallas/impl/fp"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/pallas/impl/fq"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var _ curves.Point = (*PointPallas)(nil)

type PointPallas struct {
	value *Ep

	_ helper_types.Incomparable
}

func (*PointPallas) Curve() curves.Curve {
	return &pallasInstance
}

func (*PointPallas) CurveName() string {
	return Name
}

func (*PointPallas) Random(reader io.Reader) curves.Point {
	return &PointPallas{value: new(Ep).Random(reader)}
}

func (*PointPallas) Hash(inputs ...[]byte) curves.Point {
	return &PointPallas{value: new(Ep).Hash(bytes.Join(inputs, nil))}
}

func (*PointPallas) Identity() curves.Point {
	return &PointPallas{value: new(Ep).Identity()}
}

func (*PointPallas) Generator() curves.Point {
	return &PointPallas{value: new(Ep).Generator()}
}

func (p *PointPallas) Clone() curves.Point {
	return &PointPallas{value: new(Ep).Set(p.value)}
}

func (p *PointPallas) ClearCofactor() curves.Point {
	return p.Clone()
}

func (p *PointPallas) IsIdentity() bool {
	return p.value.IsIdentity()
}

func (p *PointPallas) IsNegative() bool {
	return p.value.GetY().IsOdd()
}

func (p *PointPallas) IsOnCurve() bool {
	return p.value.IsOnCurve()
}

func (p *PointPallas) Double() curves.Point {
	return &PointPallas{value: new(Ep).Double(p.value)}
}

func (*PointPallas) Scalar() curves.Scalar {
	return &ScalarPallas{value: new(fq.Fq).SetZero()}
}

func (p *PointPallas) Neg() curves.Point {
	return &PointPallas{value: new(Ep).Neg(p.value)}
}

func (p *PointPallas) Add(rhs curves.Point) curves.Point {
	r, ok := rhs.(*PointPallas)
	if !ok {
		return nil
	}
	return &PointPallas{value: new(Ep).Add(p.value, r.value)}
}

func (p *PointPallas) Sub(rhs curves.Point) curves.Point {
	r, ok := rhs.(*PointPallas)
	if !ok {
		return nil
	}
	return &PointPallas{value: new(Ep).Sub(p.value, r.value)}
}

func (p *PointPallas) Mul(rhs curves.Scalar) curves.Point {
	s, ok := rhs.(*ScalarPallas)
	if !ok {
		return nil
	}
	return &PointPallas{value: new(Ep).Mul(p.value, s.value)}
}

func (p *PointPallas) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*PointPallas)
	if !ok {
		return false
	}
	return p.value.Equal(r.value)
}

func (p *PointPallas) Set(x, y *saferith.Nat) (curves.Point, error) {
	xx := subtle.ConstantTimeCompare(x.Bytes(), []byte{})
	yy := subtle.ConstantTimeCompare(y.Bytes(), []byte{})
	xElem := new(fp.Fp).SetNat(x)
	var data [32]byte
	if yy == 1 {
		if xx == 1 {
			return &PointPallas{value: new(Ep).Identity()}, nil
		}
		data = xElem.Bytes()
		return p.FromAffineCompressed(data[:])
	}
	yElem := new(fp.Fp).SetNat(y)
	value := &Ep{X: xElem, Y: yElem, Z: new(fp.Fp).SetOne()}
	if !value.IsOnCurve() {
		return nil, errs.NewMembershipError("point is not on the curve")
	}
	return &PointPallas{value: value}, nil
}

func (p *PointPallas) ToAffineCompressed() []byte {
	return p.value.ToAffineCompressed()
}

func (p *PointPallas) ToAffineUncompressed() []byte {
	return p.value.ToAffineUncompressed()
}

func (*PointPallas) FromAffineCompressed(input []byte) (curves.Point, error) {
	value, err := new(Ep).FromAffineCompressed(input)
	if err != nil {
		return nil, err
	}
	return &PointPallas{value: value}, nil
}

func (*PointPallas) FromAffineUncompressed(input []byte) (curves.Point, error) {
	value, err := new(Ep).FromAffineUncompressed(input)
	if err != nil {
		return nil, err
	}
	return &PointPallas{value: value}, nil
}

func (p *PointPallas) MarshalBinary() ([]byte, error) {
	return internal.PointMarshalBinary(p)
}

func (p *PointPallas) UnmarshalBinary(input []byte) error {
	pt, err := internal.PointUnmarshalBinary(&pallasInstance, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ppt, ok := pt.(*PointPallas)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.value = ppt.value
	return nil
}

func (p *PointPallas) MarshalText() ([]byte, error) {
	return internal.PointMarshalText(p)
}

func (p *PointPallas) UnmarshalText(input []byte) error {
	pt, err := internal.PointUnmarshalText(&pallasInstance, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	ppt, ok := pt.(*PointPallas)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.value = ppt.value
	return nil
}

func (p *PointPallas) MarshalJSON() ([]byte, error) {
	return internal.PointMarshalJson(p)
}

func (p *PointPallas) UnmarshalJSON(input []byte) error {
	pt, err := internal.NewPointFromJSON(&pallasInstance, input)
	if err != nil {
		return errs.WrapSerializationError(err, "could not unmarshal")
	}
	P, ok := pt.(*PointPallas)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.value = P.value
	return nil
}

func (p *PointPallas) X() curves.FieldElement {
	return &FieldElementPallas{
		v: p.value.GetX(),
	}
}

func (p *PointPallas) Y() curves.FieldElement {
	return &FieldElementPallas{
		v: p.value.GetY(),
	}
}

func (p *PointPallas) JacobianX() curves.FieldElement {
	return &FieldElementPallas{
		v: p.value.X,
	}
}

func (p *PointPallas) JacobianY() curves.FieldElement {
	return &FieldElementPallas{
		v: p.value.Y,
	}
}

func (p *PointPallas) Jacobian() curves.FieldElement {
	return &FieldElementPallas{
		v: p.value.Z,
	}
}

func (p *PointPallas) GetEp() *Ep {
	return new(Ep).Set(p.value)
}
