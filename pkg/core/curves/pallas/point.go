package pallas

import (
	"bytes"
	"crypto/subtle"
	"io"
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/pallas/impl/fp"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/pallas/impl/fq"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

var _ (curves.Point) = (*Point)(nil)

type Point struct {
	value *Ep
}

func (Point) Curve() (curves.Curve, error) {
	return pallasInstance, nil
}

func (Point) CurveName() string {
	return Name
}

func (*Point) Random(reader io.Reader) curves.Point {
	return &Point{new(Ep).Random(reader)}
}

func (*Point) Hash(inputs ...[]byte) curves.Point {
	return &Point{new(Ep).Hash(bytes.Join(inputs, nil))}
}

func (*Point) Identity() curves.Point {
	return &Point{new(Ep).Identity()}
}

func (*Point) Generator() curves.Point {
	return &Point{new(Ep).Generator()}
}

func (p *Point) IsIdentity() bool {
	return p.value.IsIdentity()
}

func (p *Point) IsNegative() bool {
	return p.value.Y().IsOdd()
}

func (p *Point) IsOnCurve() bool {
	return p.value.IsOnCurve()
}

func (p *Point) Double() curves.Point {
	return &Point{new(Ep).Double(p.value)}
}

func (*Point) Scalar() curves.Scalar {
	return &Scalar{new(fq.Fq).SetZero()}
}

func (p *Point) Neg() curves.Point {
	return &Point{new(Ep).Neg(p.value)}
}

func (p *Point) Add(rhs curves.Point) curves.Point {
	r, ok := rhs.(*Point)
	if !ok {
		return nil
	}
	return &Point{new(Ep).Add(p.value, r.value)}
}

func (p *Point) Sub(rhs curves.Point) curves.Point {
	r, ok := rhs.(*Point)
	if !ok {
		return nil
	}
	return &Point{new(Ep).Sub(p.value, r.value)}
}

func (p *Point) Mul(rhs curves.Scalar) curves.Point {
	s, ok := rhs.(*Scalar)
	if !ok {
		return nil
	}
	return &Point{new(Ep).Mul(p.value, s.value)}
}

func (p *Point) Equal(rhs curves.Point) bool {
	r, ok := rhs.(*Point)
	if !ok {
		return false
	}
	return p.value.Equal(r.value)
}

func (p *Point) Set(x, y *big.Int) (curves.Point, error) {
	xx := subtle.ConstantTimeCompare(x.Bytes(), []byte{})
	yy := subtle.ConstantTimeCompare(y.Bytes(), []byte{})
	xElem := new(fp.Fp).SetBigInt(x)
	var data [32]byte
	if yy == 1 {
		if xx == 1 {
			return &Point{new(Ep).Identity()}, nil
		}
		data = xElem.Bytes()
		return p.FromAffineCompressed(data[:])
	}
	yElem := new(fp.Fp).SetBigInt(y)
	value := &Ep{xElem, yElem, new(fp.Fp).SetOne()}
	if !value.IsOnCurve() {
		return nil, errs.NewNotOnCurve("point is not on the curve")
	}
	return &Point{value}, nil
}

func (p *Point) ToAffineCompressed() []byte {
	return p.value.ToAffineCompressed()
}

func (p *Point) ToAffineUncompressed() []byte {
	return p.value.ToAffineUncompressed()
}

func (*Point) FromAffineCompressed(input []byte) (curves.Point, error) {
	value, err := new(Ep).FromAffineCompressed(input)
	if err != nil {
		return nil, err
	}
	return &Point{value}, nil
}

func (*Point) FromAffineUncompressed(input []byte) (curves.Point, error) {
	value, err := new(Ep).FromAffineUncompressed(input)
	if err != nil {
		return nil, err
	}
	return &Point{value}, nil
}

func (p *Point) MarshalBinary() ([]byte, error) {
	return internal.PointMarshalBinary(p)
}

func (p *Point) UnmarshalBinary(input []byte) error {
	pt, err := internal.PointUnmarshalBinary(pallasInstance, input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*Point)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.value = ppt.value
	return nil
}

func (p *Point) MarshalText() ([]byte, error) {
	return internal.PointMarshalText(p)
}

func (p *Point) UnmarshalText(input []byte) error {
	pt, err := internal.PointUnmarshalText(pallasInstance, input)
	if err != nil {
		return err
	}
	ppt, ok := pt.(*Point)
	if !ok {
		return errs.NewInvalidType("invalid point")
	}
	p.value = ppt.value
	return nil
}

func (p *Point) MarshalJSON() ([]byte, error) {
	return internal.PointMarshalJson(p)
}

func (p *Point) UnmarshalJSON(input []byte) error {
	pt, err := internal.NewPointFromJSON(pallasInstance, input)
	if err != nil {
		return errs.WrapFailed(err, "could not extract a point from json")
	}
	P, ok := pt.(*Point)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	p.value = P.value
	return nil
}

func (p *Point) X() curves.FieldElement {
	return FieldElement{
		v: p.value.X(),
	}
}

func (p *Point) Y() curves.FieldElement {
	return FieldElement{
		v: p.value.Y(),
	}
}

func (p *Point) GetEp() *Ep {
	return new(Ep).Set(p.value)
}
