package p256

import (
	"reflect"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	p256n "github.com/copperexchange/knox-primitives/pkg/core/curves/p256/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256/impl/fp"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256/impl/fq"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

const Name = "P-256"

var (
	p256Initonce sync.Once
	p256Instance CurveP256
)

var _ curves.CurveProfile = (*CurveProfileP256)(nil)

type CurveProfileP256 struct{}

func (*CurveProfileP256) Field() curves.FieldProfile {
	return new(FieldProfileP256)
}

func (*CurveProfileP256) SubGroupOrder() *saferith.Modulus {
	return fq.New().Params.Modulus
}

func (*CurveProfileP256) Cofactor() curves.Scalar {
	return (&p256Instance).Scalar().One()
}

func (*CurveProfileP256) ToPairingCurve() curves.PairingCurve {
	return nil
}

var _ curves.Curve = (*CurveP256)(nil)

type CurveP256 struct {
	Scalar_  curves.Scalar
	Point_   curves.Point
	Name_    string
	Profile_ curves.CurveProfile

	_ helper_types.Incomparable
}

func p256Init() {
	p256Instance = CurveP256{
		Scalar_:  new(ScalarP256).Zero(),
		Point_:   new(PointP256).Identity(),
		Name_:    Name,
		Profile_: &CurveProfileP256{},
	}
}

func New() *CurveP256 {
	p256Initonce.Do(p256Init)
	return &p256Instance
}

func (c *CurveP256) Profile() curves.CurveProfile {
	return c.Profile_
}

func (c *CurveP256) Scalar() curves.Scalar {
	return c.Scalar_
}

func (c *CurveP256) Point() curves.Point {
	return c.Point_
}

func (c *CurveP256) Name() string {
	return c.Name_
}

func (c *CurveP256) Generator() curves.Point {
	return c.Point_.Generator()
}

func (c *CurveP256) Identity() curves.Point {
	return c.Point_.Identity()
}

func (c *CurveP256) ScalarBaseMult(sc curves.Scalar) curves.Point {
	return c.Generator().Mul(sc)
}

func (*CurveP256) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	nPoints := make([]*impl.EllipticPoint, len(points))
	nScalars := make([]*impl.Field, len(scalars))
	for i, pt := range points {
		ptv, ok := pt.(*PointP256)
		if !ok {
			return nil, errs.NewFailed("invalid point type %s, expected PointP256", reflect.TypeOf(pt).Name())
		}
		nPoints[i] = ptv.Value
	}
	for i, sc := range scalars {
		s, ok := sc.(*ScalarP256)
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
	return &PointP256{Value: value}, nil
}

func (*CurveP256) DeriveAffine(x curves.FieldElement) (evenY, oddY curves.Point, err error) {
	xc, ok := x.(*FieldElementP256)
	if !ok {
		return nil, nil, errs.NewInvalidType("provided x coordinate is not a p256 field element")
	}
	rhs := fp.New()
	new(PointP256).Value.Arithmetic.RhsEq(rhs, xc.v)
	y, wasQr := fp.New().Sqrt(rhs)
	if !wasQr {
		return nil, nil, errs.NewInvalidCoordinates("x was not a quadratic residue")
	}
	p1e := p256n.PointNew().Identity()
	p1e.X = xc.v
	p1e.Y = y
	p1e.Z.SetOne()

	p2e := p256n.PointNew().Identity()
	p2e.X = xc.v
	p2e.Y = fp.New().Neg(y)
	p2e.Z.SetOne()

	p1 := &PointP256{Value: p1e}
	p2 := &PointP256{Value: p2e}

	if p1.Y().IsEven() {
		return p1, p2, nil
	}
	return p2, p1, nil
}
