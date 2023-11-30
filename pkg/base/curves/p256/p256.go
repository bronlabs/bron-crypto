package p256

import (
	"reflect"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	p256n "github.com/copperexchange/krypton-primitives/pkg/base/curves/p256/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256/impl/fp"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256/impl/fq"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	hashing "github.com/copperexchange/krypton-primitives/pkg/hashing/hash2curve"
)

type CurveIdentifierP256 struct {
	curves.CurveIdentifier
}

const Name = "P256" // Compliant with Hash2curve (https://datatracker.ietf.org/doc/html/rfc9380)

var (
	p256Initonce sync.Once
	p256Instance CurveP256
)

var _ curves.CurveProfile[CurveIdentifierP256] = (*CurveProfileP256)(nil)

type CurveProfileP256 struct{}

func (*CurveProfileP256) Field() curves.FieldProfile {
	return new(FieldProfile)
}

func (*CurveProfileP256) SubGroupOrder() *saferith.Modulus {
	return fq.New().Params.Modulus
}

func (*CurveProfileP256) Cofactor() curves.Scalar[CurveIdentifierP256] {
	return (&p256Instance).Scalar().One()
}

func (*CurveProfileP256) ToPairingCurve() curves.PairingCurve[CurveIdentifierP256] {
	return nil
}

var _ curves.Curve[CurveIdentifierP256] = (*CurveP256)(nil)

type CurveP256 struct {
	Scalar_       curves.Scalar[CurveIdentifierP256]
	Point_        curves.Point[CurveIdentifierP256]
	FieldElement_ curves.FieldElement[CurveIdentifierP256]
	Name_         string
	Profile_      curves.CurveProfile[CurveIdentifierP256]

	hashing.CurveHasher[CurveIdentifierP256]

	_ types.Incomparable
}

func p256Init() {
	p256Instance = CurveP256{
		Scalar_:       new(ScalarP256).Zero(),
		Point_:        new(PointP256).Identity(),
		FieldElement_: new(FieldElementP256).Zero(),
		Name_:         Name,
		Profile_:      &CurveProfileP256{},
	}
	p256Instance.CurveHasher = hashing.NewCurveHasherSha256(
		New(),
		base.HASH2CURVE_APP_TAG,
		hashing.DST_TAG_SSWU,
	)
}

func New() curves.Curve[CurveIdentifierP256] {
	p256Initonce.Do(p256Init)
	return &p256Instance
}

// SetHasherAppTag sets the hasher to use for hash-to-curve operations with a
// custom "appTag". Not exposed in the `curves.Curve` interface, as by
// default we should use the library-wide HASH2CURVE_APP_TAG for compatibility.
func (c *CurveP256) SetHasherAppTag(appTag string) {
	c.CurveHasher = hashing.NewCurveHasherSha256(
		New(),
		appTag,
		hashing.DST_TAG_SSWU,
	)
}

func (c *CurveP256) Profile() curves.CurveProfile[CurveIdentifierP256] {
	return c.Profile_
}

func (c *CurveP256) Scalar() curves.Scalar[CurveIdentifierP256] {
	return c.Scalar_
}

func (c *CurveP256) Point() curves.Point[CurveIdentifierP256] {
	return c.Point_
}

func (c *CurveP256) Name() string {
	return c.Name_
}

func (c *CurveP256) FieldElement() curves.FieldElement[CurveIdentifierP256] {
	return c.FieldElement_
}

func (c *CurveP256) Generator() curves.Point[CurveIdentifierP256] {
	return c.Point_.Generator()
}

func (c *CurveP256) Identity() curves.Point[CurveIdentifierP256] {
	return c.Point_.Identity()
}

func (c *CurveP256) ScalarBaseMult(sc curves.Scalar[CurveIdentifierP256]) curves.Point[CurveIdentifierP256] {
	return c.Generator().Mul(sc)
}

func (*CurveP256) MultiScalarMult(scalars []curves.Scalar[CurveIdentifierP256], points []curves.Point[CurveIdentifierP256]) (curves.Point[CurveIdentifierP256], error) {
	nPoints := make([]*impl.EllipticPoint, len(points))
	nScalars := make([]*impl.FieldValue, len(scalars))
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

func (c *CurveP256) DeriveFromAffineX(x curves.FieldElement[CurveIdentifierP256]) (evenY, oddY curves.Point[CurveIdentifierP256], err error) {
	xc, ok := x.(*FieldElementP256)
	if !ok {
		return nil, nil, errs.NewInvalidType("provided x coordinate is not a p256 field element")
	}
	rhs := fp.New()
	cp, ok := c.Point().(*PointP256)
	if !ok {
		return nil, nil, errs.NewInvalidType("provided point is not a p256 point")
	}
	cp.Value.Arithmetic.RhsEq(rhs, xc.v)
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

	p1 := &PointP256{Value: p1e}
	p2 := &PointP256{Value: p2e}

	if p1.Y().IsEven() {
		return p1, p2, nil
	}
	return p2, p1, nil
}
