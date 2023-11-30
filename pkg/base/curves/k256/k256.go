package k256

import (
	"reflect"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	secp256k1 "github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl/fp"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl/fq"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	hashing "github.com/copperexchange/krypton-primitives/pkg/hashing/hash2curve"
)

type CurveIdentifierK256 struct {
	curves.CurveIdentifier
}

const Name = "secp256k1" // Compliant with Hash2curve (https://datatracker.ietf.org/doc/html/rfc9380)

var (
	k256Initonce sync.Once
	k256Instance CurveK256
)

var _ curves.CurveProfile[CurveIdentifierK256] = (*CurveProfileK256)(nil)

type CurveProfileK256 struct{}

func (*CurveProfileK256) Field() curves.FieldProfile {
	return &FieldProfileK256{}
}

func (*CurveProfileK256) SubGroupOrder() *saferith.Modulus {
	return fq.New().Params.Modulus
}

func (*CurveProfileK256) Cofactor() curves.Scalar[CurveIdentifierK256] {
	return (&k256Instance).Scalar().One()
}

func (*CurveProfileK256) ToPairingCurve() curves.PairingCurve[CurveIdentifierK256] {
	return nil
}

var _ curves.Curve[CurveIdentifierK256] = (*CurveK256)(nil)

type CurveK256 struct {
	Scalar_       curves.Scalar[CurveIdentifierK256]
	Point_        curves.Point[CurveIdentifierK256]
	FieldElement_ curves.FieldElement[CurveIdentifierK256]
	Name_         string
	Profile_      curves.CurveProfile[CurveIdentifierK256]

	hashing.CurveHasher[CurveIdentifierK256]

	_ types.Incomparable
}

func k256Init() {
	k256Instance = CurveK256{
		Scalar_:       new(ScalarK256).Zero(),
		Point_:        new(PointK256).Identity(),
		FieldElement_: new(FieldElementK256).Zero(),
		Name_:         Name,
		Profile_:      &CurveProfileK256{},
	}
	k256Instance.CurveHasher = hashing.NewCurveHasherSha256(
		New(),
		base.HASH2CURVE_APP_TAG,
		hashing.DST_TAG_SSWU,
	)
}

func New() curves.Curve[CurveIdentifierK256] {
	k256Initonce.Do(k256Init)
	return &k256Instance
}

// SetHasherAppTag sets the hasher to use for hash-to-curve operations with a
// custom "appTag". Not exposed in the `curves.Curve` interface, as by
// default we should use the library-wide HASH2CURVE_APP_TAG for compatibility.
func (c CurveK256) SetHasherAppTag(appTag string) {
	c.CurveHasher = hashing.NewCurveHasherSha256(
		New(),
		appTag,
		hashing.DST_TAG_SSWU,
	)
}

func (c CurveK256) Profile() curves.CurveProfile[CurveIdentifierK256] {
	return c.Profile_
}

func (c CurveK256) Scalar() curves.Scalar[CurveIdentifierK256] {
	return c.Scalar_
}

func (c CurveK256) Point() curves.Point[CurveIdentifierK256] {
	return c.Point_
}

func (c CurveK256) Name() string {
	return c.Name_
}

func (c CurveK256) FieldElement() curves.FieldElement[CurveIdentifierK256] {
	return c.FieldElement_
}

func (c CurveK256) Generator() curves.Point[CurveIdentifierK256] {
	return c.Point_.Generator()
}

func (c CurveK256) Identity() curves.Point[CurveIdentifierK256] {
	return c.Point_.Identity()
}

func (c CurveK256) ScalarBaseMult(sc curves.Scalar[CurveIdentifierK256]) curves.Point[CurveIdentifierK256] {
	return c.Generator().Mul(sc)
}

func (CurveK256) MultiScalarMult(scalars []curves.Scalar[CurveIdentifierK256], points []curves.Point[CurveIdentifierK256]) (curves.Point[CurveIdentifierK256], error) {
	nPoints := make([]*impl.EllipticPoint, len(points))
	nScalars := make([]*impl.FieldValue, len(scalars))
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

func (c CurveK256) DeriveFromAffineX(x curves.FieldElement[CurveIdentifierK256]) (evenY, oddY curves.Point[CurveIdentifierK256], err error) {
	xc, ok := x.(*FieldElementK256)
	if !ok {
		return nil, nil, errs.NewInvalidType("provided x coordinate is not a k256 field element")
	}
	rhs := fp.New()
	cPoint, ok := c.Point().(*PointK256)
	if !ok {
		return nil, nil, errs.NewFailed("invalid point type %s, expected PointK256", reflect.TypeOf(c.Point()).Name())
	}
	cPoint.Value.Arithmetic.RhsEq(rhs, xc.v)
	y, wasQr := fp.New().Sqrt(rhs)
	if !wasQr {
		return nil, nil, errs.NewInvalidCoordinates("x was not a quadratic residue")
	}
	p1e := secp256k1.PointNew().Identity()
	p1e.X = xc.v
	p1e.Y = fp.New().Set(y)
	p1e.Z.SetOne()

	p2e := secp256k1.PointNew().Identity()
	p2e.X = xc.v
	p2e.Y = fp.New().Neg(fp.New().Set(y))
	p2e.Z.SetOne()

	p1 := &PointK256{Value: p1e}
	p2 := &PointK256{Value: p2e}

	if p1.Y().IsEven() {
		return p1, p2, nil
	}
	return p2, p1, nil
}
