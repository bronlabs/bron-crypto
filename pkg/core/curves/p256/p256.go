package p256

import (
	"reflect"
	"sync"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	p256n "github.com/copperexchange/knox-primitives/pkg/core/curves/p256/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

const Name = "P-256"

var (
	p256Initonce sync.Once
	p256Instance Curve
)

var _ (curves.Curve) = (*Curve)(nil)

type Curve struct {
	Sc curves.Scalar
	P  curves.Point
	ID string
}

func p256Init() {
	p256Instance = Curve{
		Sc: new(Scalar).Zero(),
		P:  new(Point).Identity(),
		ID: Name,
	}
}

func New() *Curve {
	p256Initonce.Do(p256Init)
	return &p256Instance
}

func (c Curve) Scalar() curves.Scalar {
	return c.Sc
}

func (c Curve) Point() curves.Point {
	return c.P
}

func (c Curve) Name() string {
	return c.ID
}

func (c Curve) Generator() curves.Point {
	return c.P.Generator()
}

func (c Curve) Identity() curves.Point {
	return c.P.Identity()
}

func (c Curve) ScalarBaseMult(sc curves.Scalar) curves.Point {
	return c.Generator().Mul(sc)
}

func (Curve) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	nPoints := make([]*impl.EllipticPoint, len(points))
	nScalars := make([]*impl.Field, len(scalars))
	for i, pt := range points {
		ptv, ok := pt.(*Point)
		if !ok {
			return nil, errs.NewFailed("invalid point type %s, expected PointP256", reflect.TypeOf(pt).Name())
		}
		nPoints[i] = ptv.Value
	}
	for i, sc := range scalars {
		s, ok := sc.(*Scalar)
		if !ok {
			return nil, errs.NewFailed("invalid scalar type %s, expected ScalarP256", reflect.TypeOf(sc).Name())
		}
		nScalars[i] = s.Value
	}
	value := p256n.PointNew()
	_, err := value.SumOfProducts(nPoints, nScalars)
	if err != nil {
		return nil, errs.WrapFailed(err, "multiscalar multiplication")
	}
	return &Point{value}, nil
}

func (Curve) DeriveAffine(x curves.Element) (curves.Point, curves.Point, error) {
	return nil, nil, nil
}
