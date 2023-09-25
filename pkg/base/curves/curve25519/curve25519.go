package curve25519

import "github.com/copperexchange/krypton-primitives/pkg/base/curves"

const Name = "Curve25519"

var _ curves.Curve = (*Curve)(nil)

type Curve struct{}

func New() *Curve {
	return &Curve{}
}

func (*Curve) Profile() curves.CurveProfile {
	return nil
}

func (*Curve) Scalar() curves.Scalar {
	return nil
}

func (*Curve) Point() curves.Point {
	return nil
}

func (*Curve) Name() string {
	return Name
}

func (*Curve) Generator() curves.Point {
	return nil
}

func (*Curve) Identity() curves.Point {
	return nil
}

func (*Curve) ScalarBaseMult(sc curves.Scalar) curves.Point {
	return nil
}

func (*Curve) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	return nil, nil
}

func (*Curve) DeriveFromAffineX(x curves.FieldElement) (curves.Point, curves.Point, error) {
	return nil, nil, nil
}
