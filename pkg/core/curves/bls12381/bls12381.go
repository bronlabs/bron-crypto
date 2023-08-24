package bls12381

import (
	"strings"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	bls12381impl "github.com/copperexchange/knox-primitives/pkg/core/curves/bls12381/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

const (
	G1Name = "BLS12381G1"
	G2Name = "BLS12381G2"
	GtName = "BLS12381Gt"
	Name   = "BLS12831"
)

var (
	bls12381g1Initonce sync.Once
	bls12381g1         CurveBls12381

	bls12381g2Initonce sync.Once
	bls12381g2         CurveBls12381
)

var (
	p, _          = saferith.ModulusFromHex(strings.ToUpper("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"))
	r, _          = saferith.ModulusFromHex(strings.ToUpper("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"))
	cofactorG2, _ = new(saferith.Nat).SetHex(strings.ToUpper("0x396C8C005555E1568C00AAAB0000AAAB"))
)

var _ curves.CurveProfile = (*CurveProfileBls12381)(nil)

type CurveProfileBls12381 struct {
	i        curves.Curve
	cofactor *saferith.Nat
	profile  curves.FieldProfile
}

func (c *CurveProfileBls12381) Field() curves.FieldProfile {
	return c.profile
}

func (*CurveProfileBls12381) SubGroupOrder() *saferith.Modulus {
	return r
}

func (c *CurveProfileBls12381) Cofactor() curves.Scalar {
	result, _ := c.i.Scalar().SetNat(c.cofactor)
	return result
}

func (*CurveProfileBls12381) ToPairingCurve() curves.PairingCurve {
	return New()
}

type PairingCurveProfile struct{}

func (*PairingCurveProfile) EmbeddingDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(12)
}

var _ curves.Curve = (*CurveBls12381)(nil)

type CurveBls12381 struct {
	Scalar_  curves.Scalar
	Point_   curves.Point
	Name_    string
	Profile_ curves.CurveProfile

	_ helper_types.Incomparable
}

var _ curves.PairingCurve = (*PairingCurve)(nil)

type PairingCurve struct {
	PairingCurveProfile_ curves.PairingCurveProfile
	G1_                  *CurveBls12381
	G2_                  *CurveBls12381
	GT_                  curves.Scalar
	Name_                string

	_ helper_types.Incomparable
}

func bls12381g1Init() {
	bls12381g1 = CurveBls12381{
		Scalar_: &ScalarBls12381{
			Value:  bls12381impl.FqNew(),
			Point_: new(PointG1),
		},
		Point_: new(PointG1).Identity(),
		Name_:  G1Name,
		Profile_: &CurveProfileBls12381{
			i:        &bls12381g1,
			cofactor: new(saferith.Nat).SetUint64(1),
			profile:  &FieldProfileG1{},
		},
	}
}

func NewG1() *CurveBls12381 {
	bls12381g1Initonce.Do(bls12381g1Init)
	return &bls12381g1
}

func bls12381g2Init() {
	bls12381g2 = CurveBls12381{
		Scalar_: &ScalarBls12381{
			Value:  bls12381impl.FqNew(),
			Point_: new(PointG2),
		},
		Point_: new(PointG2).Identity(),
		Name_:  G2Name,
		Profile_: &CurveProfileBls12381{
			i:        &bls12381g2,
			cofactor: cofactorG2,
			profile:  &FieldProfileG2{},
		},
	}
}

func NewG2() *CurveBls12381 {
	bls12381g2Initonce.Do(bls12381g2Init)
	return &bls12381g2
}

func New() *PairingCurve {
	return &PairingCurve{
		G1_: NewG1(),
		G2_: NewG2(),
		GT_: &ScalarGt{
			Value: new(bls12381impl.Gt).SetOne(),
		},
		Name_:                Name,
		PairingCurveProfile_: &PairingCurveProfile{},
	}
}

func (c *CurveBls12381) Profile() curves.CurveProfile {
	return c.Profile_
}

func (c *CurveBls12381) Scalar() curves.Scalar {
	return c.Scalar_
}

func (c *CurveBls12381) Point() curves.Point {
	return c.Point_
}

func (c *CurveBls12381) Name() string {
	return c.Name_
}

func (c *CurveBls12381) Generator() curves.Point {
	return c.Point_.Generator()
}

func (c *CurveBls12381) Identity() curves.Point {
	return c.Point_.Identity()
}

func (c *CurveBls12381) ScalarBaseMult(sc curves.Scalar) curves.Point {
	return c.Generator().Mul(sc)
}

func (c *CurveBls12381) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
	var result curves.Point
	var err error
	if c.Name() == G1Name {
		result, err = multiScalarMultBls12381G1(scalars, points)
	} else {
		result, err = multiScalarMultBls12381G2(scalars, points)
	}
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't do msm")
	}
	return result, nil
}

func (*CurveBls12381) DeriveAffine(x curves.FieldElement) (curves.Point, curves.Point, error) {
	return nil, nil, nil
}

func (pc *PairingCurve) PairingCurveProfile() curves.PairingCurveProfile {
	return pc.PairingCurveProfile_
}

func (pc *PairingCurve) Name() string {
	return pc.Name_
}

func (*PairingCurve) G1() curves.Curve {
	return &bls12381g1
}

func (PairingCurve) PointG1() curves.PairingPoint {
	return bls12381g1.Point().(curves.PairingPoint)
}

func (PairingCurve) PointG2() curves.PairingPoint {
	return bls12381g2.Point().(curves.PairingPoint)
}

func (*PairingCurve) G2() curves.Curve {
	return &bls12381g2
}

func (pc *PairingCurve) Gt() curves.Scalar {
	return pc.GT_
}

func (*PairingCurve) Pairing(pG1, pG2 curves.PairingPoint) curves.Scalar {
	return pG1.Pairing(pG2)
}

func (*PairingCurve) MultiPairing(points ...curves.PairingPoint) curves.Scalar {
	if len(points)%2 != 0 {
		return nil
	}
	valid := true
	eng := new(bls12381impl.Engine)
	for i := 0; i < len(points); i += 2 {
		pt1, ok := points[i].(*PointG1)
		valid = valid && ok
		pt2, ok := points[i+1].(*PointG2)
		valid = valid && ok
		if valid {
			eng.AddPair(pt1.Value, pt2.Value)
		}
	}
	if !valid {
		return nil
	}

	value := eng.Result()
	return &ScalarGt{Value: value}
}
