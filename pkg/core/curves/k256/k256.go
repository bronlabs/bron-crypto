package k256

import (
	"reflect"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	secp256k1 "github.com/copperexchange/knox-primitives/pkg/core/curves/k256/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256/impl/fp"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256/impl/fq"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

const Name = "secp256k1"

var (
	k256Initonce sync.Once
	k256Instance CurveK256
)

var _ curves.CurveProfile = (*CurveProfileK256)(nil)

type CurveProfileK256 struct{}

func (*CurveProfileK256) Field() curves.FieldProfile {
	return &FieldProfileK256{}
}

func (*CurveProfileK256) SubGroupOrder() *saferith.Modulus {
	return fq.New().Params.Modulus
}

func (*CurveProfileK256) Cofactor() curves.Scalar {
	return (&k256Instance).Scalar().One()
}

func (*CurveProfileK256) ToPairingCurve() curves.PairingCurve {
	return nil
}

var _ curves.Curve = (*CurveK256)(nil)

type CurveK256 struct {
	Scalar_  curves.Scalar
	Point_   curves.Point
	Name_    string
	Profile_ *CurveProfileK256

	_ helper_types.Incomparable
}

func k256Init() {
	k256Instance = CurveK256{
		Scalar_:  new(ScalarK256).Zero(),
		Point_:   new(PointK256).Identity(),
		Name_:    Name,
		Profile_: &CurveProfileK256{},
	}
}

func New() *CurveK256 {
	k256Initonce.Do(k256Init)
	return &k256Instance
}

func (c *CurveK256) Profile() curves.CurveProfile {
	return c.Profile_
}

func (c *CurveK256) Scalar() curves.Scalar {
	return c.Scalar_
}

func (c *CurveK256) Point() curves.Point {
	return c.Point_
}

func (c *CurveK256) Name() string {
	return c.Name_
}

func (c *CurveK256) Generator() curves.Point {
	return c.Point_.Generator()
}

func (c *CurveK256) Identity() curves.Point {
	return c.Point_.Identity()
}

func (c *CurveK256) ScalarBaseMult(sc curves.Scalar) curves.Point {
	return c.Generator().Mul(sc)
}

func (*CurveK256) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	nPoints := make([]*impl.EllipticPoint, len(points))
	nScalars := make([]*impl.Field, len(scalars))
	for i, pt := range points {
		ptv, ok := pt.(*PointK256)
		if !ok {
			return nil, errs.NewFailed("invalid point type %s, expected PointK256", reflect.TypeOf(pt).Name())
		}
		nPoints[i] = ptv.Value
	}
	for i, sc := range scalars {
		s, ok := sc.(*ScalarK256)
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
	return &PointK256{Value: value}, nil
}

// DeriveAffine TODO: implement
func (*CurveK256) DeriveAffine(x curves.FieldElement) (evenY, oddY curves.Point, err error) {
	xc, ok := x.(*FieldElementK256)
	if !ok {
		return nil, nil, errs.NewInvalidType("provided x coordinate is not a k256 field element")
	}
	rhs := fp.New()
	new(PointK256).Value.Arithmetic.RhsEq(rhs, xc.v)
	y, wasQr := fp.New().Sqrt(rhs)
	if !wasQr {
		return nil, nil, errs.NewInvalidCoordinates("x was not a quadratic residue")
	}
	p1e := secp256k1.PointNew().Identity()
	p1e.X = xc.v
	p1e.Y = y
	p1e.Z.SetOne()

	p2e := secp256k1.PointNew().Identity()
	p2e.X = xc.v
	p2e.Y = fp.New().Neg(y)
	p2e.Z.SetOne()

	p1 := &PointK256{Value: p1e}
	p2 := &PointK256{Value: p2e}

	if p1.Y().IsEven() {
		return p1, p2, nil
	}
	return p2, p1, nil
}
