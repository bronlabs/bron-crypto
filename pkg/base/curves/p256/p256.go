package p256

import (
	"reflect"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/impl"
	p256n "github.com/copperexchange/knox-primitives/pkg/base/curves/p256/impl"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/p256/impl/fp"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/p256/impl/fq"
	"github.com/copperexchange/knox-primitives/pkg/base/errs"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
)

const Name = "P-256"

var (
	p256Initonce sync.Once
	p256Instance Curve
)

var _ curves.CurveProfile = (*CurveProfile)(nil)

type CurveProfile struct{}

func (*CurveProfile) Field() curves.FieldProfile {
	return new(FieldProfile)
}

func (*CurveProfile) SubGroupOrder() *saferith.Modulus {
	return fq.New().Params.Modulus
}

func (*CurveProfile) Cofactor() curves.Scalar {
	return (&p256Instance).Scalar().One()
}

func (*CurveProfile) ToPairingCurve() curves.PairingCurve {
	return nil
}

var _ curves.Curve = (*Curve)(nil)

type Curve struct {
	Scalar_  curves.Scalar
	Point_   curves.Point
	Name_    string
	Profile_ curves.CurveProfile

	_ helper_types.Incomparable
}

func p256Init() {
	p256Instance = Curve{
		Scalar_:  new(Scalar).Zero(),
		Point_:   new(Point).Identity(),
		Name_:    Name,
		Profile_: &CurveProfile{},
	}
}

func New() *Curve {
	p256Initonce.Do(p256Init)
	return &p256Instance
}

func (c *Curve) Profile() curves.CurveProfile {
	return c.Profile_
}

func (c *Curve) Scalar() curves.Scalar {
	return c.Scalar_
}

func (c *Curve) Point() curves.Point {
	return c.Point_
}

func (c *Curve) Name() string {
	return c.Name_
}

func (c *Curve) Generator() curves.Point {
	return c.Point_.Generator()
}

func (c *Curve) Identity() curves.Point {
	return c.Point_.Identity()
}

func (c *Curve) ScalarBaseMult(sc curves.Scalar) curves.Point {
	return c.Generator().Mul(sc)
}

func (*Curve) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
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
	return &Point{Value: value}, nil
}

func (c *Curve) DeriveFromAffineX(x curves.FieldElement) (evenY, oddY curves.Point, err error) {
	xc, ok := x.(*FieldElement)
	if !ok {
		return nil, nil, errs.NewInvalidType("provided x coordinate is not a p256 field element")
	}
	rhs := fp.New()
	c.Point().(*Point).Value.Arithmetic.RhsEq(rhs, xc.v)
	y, wasQr := fp.New().Sqrt(rhs)
	if !wasQr {
		return nil, nil, errs.NewInvalidCoordinates("x was not a quadratic residue")
	}
	p1e := p256n.PointNew().Identity()
	p1e.X = xc.v
	p1e.Y = fp.New().Set(y)
	p1e.Z.SetOne()

	p2e := p256n.PointNew().Identity()
	p2e.X = xc.v
	p2e.Y = fp.New().Neg(fp.New().Set(y))
	p2e.Z.SetOne()

	p1 := &Point{Value: p1e}
	p2 := &Point{Value: p2e}

	if p1.Y().IsEven() {
		return p1, p2, nil
	}
	return p2, p1, nil
}
