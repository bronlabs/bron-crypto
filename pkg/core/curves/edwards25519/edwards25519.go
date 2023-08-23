package edwards25519

import (
	"reflect"
	"strings"
	"sync"

	filippo "filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

const Name = "edwards25519"

var (
	edwards25519Initonce sync.Once
	edwards25519Instance CurveEd25519

	scOne, _   = filippo.NewScalar().SetCanonicalBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	scMinusOne = [32]byte{236, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16}

	subgroupOrder, _  = saferith.ModulusFromHex(strings.ToUpper("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"))
	baseFieldOrder, _ = saferith.ModulusFromHex(strings.ToUpper("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"))

	// d is a constant in the curve equation.
	d, _ = new(field.Element).SetBytes([]byte{
		0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
		0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
		0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
		0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
	})
)

var _ curves.CurveProfile = (*CurveProfileEd25519)(nil)

type CurveProfileEd25519 struct{}

func (*CurveProfileEd25519) Field() curves.FieldProfile {
	return &FieldProfileEd25519{}
}

func (*CurveProfileEd25519) SubGroupOrder() *saferith.Modulus {
	return subgroupOrder
}

func (*CurveProfileEd25519) Cofactor() curves.Scalar {
	return (&edwards25519Instance).Scalar().New(8)
}

func (*CurveProfileEd25519) ToPairingCurve() curves.PairingCurve {
	return nil
}

var _ curves.Curve = (*CurveEd25519)(nil)

type CurveEd25519 struct {
	Scalar_  curves.Scalar
	Point_   curves.Point
	Name_    string
	Profile_ curves.CurveProfile

	_ helper_types.Incomparable
}

func New() *CurveEd25519 {
	edwards25519Initonce.Do(ed25519Init)
	return &edwards25519Instance
}

func ed25519Init() {
	edwards25519Instance = CurveEd25519{
		Scalar_:  new(ScalarEd25519).Zero(),
		Point_:   new(PointEd25519).Identity(),
		Name_:    Name,
		Profile_: &CurveProfileEd25519{},
	}
}

func (c *CurveEd25519) Profile() curves.CurveProfile {
	return c.Profile_
}

func (c *CurveEd25519) Scalar() curves.Scalar {
	return c.Scalar_
}

func (c *CurveEd25519) Point() curves.Point {
	return c.Point_
}

func (c *CurveEd25519) Name() string {
	return c.Name_
}

func (c *CurveEd25519) Generator() curves.Point {
	return c.Point_.Generator()
}

func (c *CurveEd25519) Identity() curves.Point {
	return c.Point_.Identity()
}

func (c *CurveEd25519) ScalarBaseMult(sc curves.Scalar) curves.Point {
	return c.Generator().Mul(sc)
}

func (*CurveEd25519) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	nScalars := make([]*filippo.Scalar, len(scalars))
	nPoints := make([]*filippo.Point, len(points))
	for i, sc := range scalars {
		s, err := filippo.NewScalar().SetCanonicalBytes(sc.Bytes())
		if err != nil {
			return nil, errs.WrapSerializationError(err, "set canonical bytes")
		}
		nScalars[i] = s
	}
	for i, pt := range points {
		pp, ok := pt.(*PointEd25519)
		if !ok {
			return nil, errs.NewFailed("invalid point type %s, expected PointEd25519", reflect.TypeOf(pt).Name())
		}
		nPoints[i] = pp.Value
	}
	pt := filippo.NewIdentityPoint().MultiScalarMult(nScalars, nPoints)
	return &PointEd25519{Value: pt}, nil
}

func (*CurveEd25519) DeriveAffine(x curves.FieldElement) (curves.Point, curves.Point, error) {
	xc, ok := x.(*FieldElementEd25519)
	if !ok {
		return nil, nil, errs.NewInvalidType("x is not an edwards25519 base field element")
	}
	xb := xc.v.Bytes()

	y, err := new(field.Element).SetBytes(xb)
	if err != nil {
		return nil, nil, errs.NewInvalidCoordinates("edwards25519: invalid point encoding length")
	}
	feOne := new(field.Element).One()

	// -x² + y² = 1 + dx²y²
	// x² + dx²y² = x²(dy² + 1) = y² - 1
	// x² = (y² - 1) / (dy² + 1)

	// u = y² - 1
	y2 := new(field.Element).Square(y)
	u := new(field.Element).Subtract(y2, feOne)

	// v = dy² + 1
	vv := new(field.Element).Multiply(y2, d)
	vv = vv.Add(vv, feOne)

	// x = +√(u/v)
	xx, wasSquare := new(field.Element).SqrtRatio(u, vv)
	if wasSquare == 0 {
		return nil, nil, errs.NewInvalidCoordinates("edwards25519: invalid point encoding")
	}

	// Select the negative square root if the sign bit is set.
	xxNeg := new(field.Element).Negate(xx)
	xx = xx.Select(xxNeg, xx, int(xb[31]>>7))

	t := new(field.Element).Multiply(xx, y)

	p1e, err := filippo.NewIdentityPoint().SetExtendedCoordinates(xx, y, feOne, t)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldnt set extended coordinates")
	}
	p1 := &PointEd25519{Value: p1e}
	p2 := p1.Neg()

	if p1.Y().IsEven() {
		return p1, p2, nil
	}
	return p2, p1, nil
}
