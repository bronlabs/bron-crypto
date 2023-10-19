package bls12381

import (
	"strings"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	bls12381impl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

const (
	G1Name = "BLS12381G1"
	G2Name = "BLS12381G2"
	GtName = "BLS12381Gt"
	Name   = "BLS12381"
)

var (
	bls12381g1Initonce sync.Once
	bls12381g1         Curve

	bls12381g2Initonce sync.Once
	bls12381g2         Curve
)

var (
	p, _          = saferith.ModulusFromHex(strings.ToUpper("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"))
	r, _          = saferith.ModulusFromHex(strings.ToUpper("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"))
	cofactorG1, _ = new(saferith.Nat).SetHex(strings.ToUpper("396C8C005555E1568C00AAAB0000AAAB"))
	cofactorG2, _ = new(saferith.Nat).SetHex(strings.ToUpper("5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5"))
)

var _ curves.CurveProfile = (*CurveProfile)(nil)

type CurveProfile struct {
	i        curves.Curve
	cofactor *saferith.Nat
	profile  curves.FieldProfile
}

func (c *CurveProfile) Field() curves.FieldProfile {
	return c.profile
}

func (*CurveProfile) SubGroupOrder() *saferith.Modulus {
	return r
}

func (c *CurveProfile) Cofactor() curves.Scalar {
	result, _ := c.i.Scalar().SetNat(c.cofactor)
	return result
}

func (*CurveProfile) ToPairingCurve() curves.PairingCurve {
	return New()
}

type PairingCurveProfile struct{}

func (*PairingCurveProfile) EmbeddingDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(12)
}

var _ curves.Curve = (*Curve)(nil)

type Curve struct {
	Scalar_       curves.Scalar
	Point_        curves.Point
	FieldElement_ curves.FieldElement
	Name_         string
	Profile_      curves.CurveProfile

	_ types.Incomparable
}

var _ curves.PairingCurve = (*PairingCurve)(nil)

type PairingCurve struct {
	PairingCurveProfile_ curves.PairingCurveProfile
	G1_                  *Curve
	G2_                  *Curve
	GT_                  curves.Scalar
	Name_                string

	_ types.Incomparable
}

func bls12381g1Init() {
	bls12381g1 = Curve{
		Scalar_: &Scalar{
			Value:  bls12381impl.FqNew(),
			Point_: new(PointG1),
		},
		Point_: new(PointG1).Identity(),
		FieldElement_: &FieldElementG1{
			v: new(bls12381impl.Fp),
		},
		Name_: G1Name,
		Profile_: &CurveProfile{
			i:        &bls12381g1,
			cofactor: cofactorG1,
			profile:  &FieldProfileG1{},
		},
	}
}

func NewG1() *Curve {
	bls12381g1Initonce.Do(bls12381g1Init)
	return &bls12381g1
}

func bls12381g2Init() {
	bls12381g2 = Curve{
		Scalar_: &Scalar{
			Value:  bls12381impl.FqNew(),
			Point_: new(PointG2),
		},
		Point_: new(PointG2).Identity(),
		Name_:  G2Name,
		Profile_: &CurveProfile{
			i:        &bls12381g2,
			cofactor: cofactorG2,
			profile:  &FieldProfileG2{},
		},
	}
}

func NewG2() *Curve {
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

func (c *Curve) FieldElement() curves.FieldElement {
	return c.FieldElement_
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

func (c *Curve) MultiScalarMult(scalars []curves.Scalar, points []curves.Point) (curves.Point, error) {
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

func (*Curve) DeriveFromAffineX(x curves.FieldElement) (p1, p2 curves.Point, err error) {
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

func (*PairingCurve) PointG1() curves.PairingPoint {
	p1, ok := bls12381g1.Point().(curves.PairingPoint)
	if !ok {
		panic("invalid point type")
	}
	return p1
}

func (*PairingCurve) PointG2() curves.PairingPoint {
	p2, ok := bls12381g2.Point().(curves.PairingPoint)
	if !ok {
		panic("invalid point type")
	}
	return p2
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
