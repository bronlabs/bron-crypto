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
)

var allCurvesMapper = map[string]curves.Curve{
	bls12381.G1Name:   bls12381.NewG1(),
	bls12381.G2Name:   bls12381.NewG2(),
	curve25519.Name:   curve25519.New(),
	edwards25519.Name: edwards25519.New(),
	k256.Name:         k256.New(),
	p256.Name:         p256.New(),
	pallas.Name:       pallas.New(),
}

// ToEllipticCurve returns the equivalent of this curve as the go interface `elliptic.Curve`.
func ToEllipticCurve(c curves.Curve) (elliptic.Curve, error) {
	switch c.Name() {
	case k256.Name:
		return k256.NewElliptic(), nil
	case p256.Name:
		return elliptic.P256(), nil
	default:
		return nil, errs.NewInvalidCurve("can't convert %s", c.Name())
	}
}

func GetCurveByName(name string) (curves.Curve, error) {
	curve, ok := allCurvesMapper[name]
	if !ok {
		return nil, errs.NewInvalidCurve("curve with name %s is not supported", name)
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
