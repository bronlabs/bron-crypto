package k256

import (
	"reflect"
	"sync"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	secp256k1 "github.com/copperexchange/knox-primitives/pkg/core/curves/k256/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

const Name = "secp256k1"

var (
	k256Initonce sync.Once
	k256Instance Curve
)

var _ (curves.Curve) = (*Curve)(nil)

type Curve struct {
	Sc curves.Scalar
	P  curves.Point
	ID string
}

func k256Init() {
	k256Instance = Curve{
		Sc: new(Scalar).Zero(),
		P:  new(Point).Identity(),
		ID: Name,
	}
}

func New() *Curve {
	k256Initonce.Do(k256Init)
	return &k256Instance
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
			return nil, errs.NewFailed("invalid point type %s, expected PointK256", reflect.TypeOf(pt).Name())
		}
		nPoints[i] = ptv.Value
	}
	for i, sc := range scalars {
		s, ok := sc.(*Scalar)
		if !ok {
			return nil, errs.NewFailed("invalid scalar type %s, expected ScalarK256", reflect.TypeOf(sc).Name())
		}
		nScalars[i] = s.Value
	}
	value := secp256k1.PointNew()
	_, err := value.SumOfProducts(nPoints, nScalars)
	if err != nil {
		return nil, errs.WrapFailed(err, "multiscalar multiplication")
	}
	return &Point{value}, nil
}

func (Curve) DeriveAffine(x curves.Element) (curves.Point, curves.Point, error) {
	return nil, nil, nil
}
