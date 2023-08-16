package bls12381

import (
	"math/big"
	"sync"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	bls12381impl "github.com/copperexchange/knox-primitives/pkg/core/curves/bls12381/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/internal"
)

const (
	G1Name = "BLS12381G1"
	G2Name = "BLS12381G2"
	GtName = "BLS12381Gt"
	Name   = "BLS12831"
)

var (
	bls12381g1Initonce sync.Once
	bls12381g1         Curve

	bls12381g2Initonce sync.Once
	bls12381g2         Curve
)

var modulus = internal.Bhex("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab")

var _ (curves.CurveProfile) = (*CurveProfile)(nil)

// TODO: finish when BLS is here
type CurveProfile struct{}

func (CurveProfile) Field() curves.FieldProfile {
	return nil
}

func (CurveProfile) SubGroupOrder() *big.Int {
	return nil
}

func (CurveProfile) Cofactor() *big.Int {
	return nil
}

type PairingCurveProfile struct{}

func (PairingCurveProfile) EmbeddingDegree() *big.Int {
	return big.NewInt(12)
}

var _ (curves.Curve) = (*Curve)(nil)

type Curve struct {
	Scalar_  curves.Scalar
	Point_   curves.Point
	Name_    string
	Profile_ curves.CurveProfile
}

var _ (curves.PairingCurve) = (*PairingCurve)(nil)

type PairingCurve struct {
	PairingCurveProfile_ curves.PairingCurveProfile
	G1_                  *Curve
	G2_                  *Curve
	GT_                  curves.Scalar
	Name_                string
}

func bls12381g1Init() {
	bls12381g1 = Curve{
		Scalar_: &Scalar{
			Value: bls12381impl.FqNew(),
			point: new(PointG1),
		},
		Point_:   new(PointG1).Identity(),
		Name_:    G1Name,
		Profile_: &CurveProfile{},
	}
}

func NewG1() *Curve {
	bls12381g1Initonce.Do(bls12381g1Init)
	return &bls12381g1
}

func bls12381g2Init() {
	bls12381g2 = Curve{
		Scalar_: &Scalar{
			Value: bls12381impl.FqNew(),
			point: new(PointG2),
		},
		Point_: new(PointG2).Identity(),
		Name_:  G2Name,
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
	return nil, nil
}

func (Curve) DeriveAffine(x curves.FieldElement) (curves.Point, curves.Point, error) {
	return nil, nil, nil
}

func (pc PairingCurve) PairingCurveProfile() curves.PairingCurveProfile {
	return pc.PairingCurveProfile_
}

func (pc PairingCurve) Name() string {
	return pc.Name_
}

func (PairingCurve) G1() curves.Curve {
	return bls12381g1
}

func (PairingCurve) G2() curves.Curve {
	return bls12381g2
}

func (pc PairingCurve) Gt() curves.Scalar {
	return pc.GT_
}

func (PairingCurve) Pairing(pG1, pG2 curves.PairingPoint) curves.Scalar {
	return pG1.Pairing(pG2)
}

func (PairingCurve) MultiPairing(points ...curves.PairingPoint) curves.Scalar {
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
	return &ScalarGt{value}
}
