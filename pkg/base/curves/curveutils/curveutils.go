package curveutils

import (
	"crypto/elliptic"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curve25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var allCurvesMapper = map[string]curves.Curve{
	bls12381.NameG1:   bls12381.NewG1(),
	bls12381.NameG2:   bls12381.NewG2(),
	curve25519.Name:   curve25519.NewCurve(),
	edwards25519.Name: edwards25519.NewCurve(),
	k256.Name:         k256.NewCurve(),
	p256.Name:         p256.NewCurve(),
	pallas.Name:       pallas.NewCurve(),
}

func GetCurveByName(name string) (curves.Curve, error) {
	curve, ok := allCurvesMapper[name]
	if !ok {
		return nil, errs.NewCurve("curve with name %s is not supported", name)
	}
	return curve, nil
}

func GetAllCurves() []curves.Curve {
	allCurves := make([]curves.Curve, 0, len(allCurvesMapper))
	for _, c := range allCurvesMapper {
		allCurves = append(allCurves, c)
	}
	return allCurves
}

// ToGoEllipticCurve returns the equivalent of this curve as the go interface `elliptic.Curve`.
func ToGoEllipticCurve(c curves.Curve) (elliptic.Curve, error) {
	switch c.Name() {
	case k256.Name:
		return k256.NewElliptic(), nil
	case p256.Name:
		return elliptic.P256(), nil
	default:
		return nil, errs.NewCurve("can't convert %s", c.Name())
	}
}

// TODO: incorporate this
func AllOfSameCurve(curve curves.Curve, xs ...any) bool {
	for _, x := range xs {
		switch t := x.(type) {
		case curves.Point:
			if curve.Name() != t.Curve().Name() {
				return false
			}
		case curves.Scalar:
			if curve.Name() != t.ScalarField().Curve().Name() {
				return false
			}
		case curves.BaseFieldElement:
			if curve.Name() != t.BaseField().Curve().Name() {
				return false
			}
		case curves.Curve:
			if curve.Name() != t.Name() {
				return false
			}
		case types.IdentityKey:
			if curve.Name() != t.PublicKey().Curve().Name() {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func AllPointsOfSameCurve(curve curves.Curve, ps ...curves.Point) bool {
	for _, p := range ps {
		if curve.Name() != p.Curve().Name() {
			return false
		}
	}
	return true
}

func AllScalarsOfSameCurve(curve curves.Curve, scs ...curves.Scalar) bool {
	for _, sc := range scs {
		if curve.Name() != sc.ScalarField().Curve().Name() {
			return false
		}
	}
	return true
}

func AllBaseFieldElementsOfSameCurve(curve curves.Curve, fes ...curves.BaseFieldElement) bool {
	for _, fe := range fes {
		if curve.Name() != fe.BaseField().Curve().Name() {
			return false
		}
	}
	return true
}

func AllCurvesAreSame(curve curves.Curve, cs ...curves.Curve) bool {
	for _, c := range cs {
		if curve.Name() != c.Name() {
			return false
		}
	}
	return true
}

func AllIdentityKeysWithSameCurve(curve curves.Curve, ks ...types.IdentityKey) bool {
	for _, k := range ks {
		if curve.Name() != k.PublicKey().Curve().Name() {
			return false
		}
	}
	return true
}
