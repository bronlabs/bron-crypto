package edwards25519

import (
	"math/big"
	"reflect"
	"sync"

	filippo "filippo.io/edwards25519"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

const Name = "edwards25519"

var (
	edwards25519Initonce sync.Once
	edwards25519Instance Curve

	scOne, _   = filippo.NewScalar().SetCanonicalBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	scMinusOne = [32]byte{236, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16}
)

var _ (curves.CurveProfile) = (*CurveProfile)(nil)

type CurveProfile struct{}

func (CurveProfile) Field() curves.FieldProfile {
	return &FieldProfile{}
}

func (CurveProfile) SubGroupOrder() *big.Int {
	return nil
}

func (CurveProfile) Cofactor() *big.Int {
	return big.NewInt(8)
}

var _ curves.Curve = (*Curve)(nil)

type Curve struct {
	Scalar_  curves.Scalar
	Point_   curves.Point
	Name_    string
	Profile_ curves.CurveProfile
}

func New() *Curve {
	edwards25519Initonce.Do(ed25519Init)
	return &edwards25519Instance
}

func ed25519Init() {
	edwards25519Instance = Curve{
		Scalar_:  new(Scalar).Zero(),
		Point_:   new(Point).Identity(),
		Name_:    Name,
		Profile_: &CurveProfile{},
	}
}

func (c Curve) Profile() curves.CurveProfile {
	return c.Profile_
}

func (c Curve) Scalar() curves.Scalar {
	return c.Scalar_
}

func (c Curve) Point() curves.Point {
	return c.Point_
}

func (c Curve) Name() string {
	return c.Name_
}

func (c Curve) Generator() curves.Point {
	return c.Point_.Generator()
}

func (c Curve) Identity() curves.Point {
	return c.Point_.Identity()
}

func (c Curve) ScalarBaseMult(sc curves.Scalar) curves.Point {
	return c.Generator().Mul(sc)
}

func (Curve) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	nScalars := make([]*filippo.Scalar, len(scalars))
	nPoints := make([]*filippo.Point, len(points))
	for i, sc := range scalars {
		s, err := filippo.NewScalar().SetCanonicalBytes(sc.Bytes())
		if err != nil {
			return nil, errs.WrapDeserializationFailed(err, "set canonical bytes")
		}
		nScalars[i] = s
	}
	for i, pt := range points {
		pp, ok := pt.(*Point)
		if !ok {
			return nil, errs.NewFailed("invalid point type %s, expected PointEd25519", reflect.TypeOf(pt).Name())
		}
		nPoints[i] = pp.Value
	}
	pt := filippo.NewIdentityPoint().MultiScalarMult(nScalars, nPoints)
	return &Point{Value: pt}, nil
}

func (Curve) DeriveAffine(x curves.FieldElement) (curves.Point, curves.Point, error) {
	return nil, nil, nil
}
