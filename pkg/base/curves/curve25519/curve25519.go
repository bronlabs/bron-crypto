package curve25519

import (
	"strings"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/constants"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	hashing "github.com/copperexchange/krypton-primitives/pkg/hashing/hash2curve"
)

const Name = constants.CURVE25519_NAME

var (
	curve25519Initonce sync.Once
	curve25519Instance Curve
	subgroupOrder, _   = saferith.ModulusFromHex(strings.ToUpper("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"))
	baseFieldOrder, _  = saferith.ModulusFromHex(strings.ToUpper("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"))
)

var _ curves.Curve = (*Curve)(nil)

type CurveProfile struct{}

func (*CurveProfile) Field() curves.FieldProfile {
	return &FieldProfile{}
}

func (*CurveProfile) SubGroupOrder() *saferith.Modulus {
	return subgroupOrder
}

func (*CurveProfile) Cofactor() curves.Scalar {
	return (&curve25519Instance).Scalar().New(8)
}

func (*CurveProfile) ToPairingCurve() curves.PairingCurve {
	return nil
}

type Curve struct {
	Scalar_  curves.Scalar
	Point_   curves.Point
	Name_    string
	Profile_ curves.CurveProfile

	hashing.CurveHasher

	_ types.Incomparable
}

func New() *Curve {
	curve25519Initonce.Do(curve25519Init)
	return &curve25519Instance
}

func curve25519Init() {
	curve25519Instance = Curve{
		Scalar_:  new(Scalar).Zero(),
		Point_:   new(Point).Identity(),
		Name_:    Name,
		Profile_: &CurveProfile{},
	}
	curve25519Instance.CurveHasher = hashing.NewCurveHasherSha512(
		&curve25519Instance,
		constants.HASH2CURVE_APP_TAG,
		hashing.DST_TAG_ELLIGATOR2,
	)
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

func (*Curve) FieldElement() curves.FieldElement {
	return nil
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
	// TODO implement me
	panic("implement me")
}

func (*Curve) DeriveFromAffineX(x curves.FieldElement) (a, b curves.Point, err error) {
	// TODO implement me
	panic("implement me")
}
