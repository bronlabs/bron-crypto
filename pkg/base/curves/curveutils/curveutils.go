package curveutils

import (
	"crypto/elliptic"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

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
	switch name {
	case k256.Name:
		return k256.New(), nil
	case bls12381.G1Name, bls12381.Name:
		return bls12381.NewG1(), nil
	case bls12381.G2Name:
		return bls12381.NewG2(), nil
	case p256.Name:
		return p256.New(), nil
	case edwards25519.Name:
		return edwards25519.New(), nil
	case pallas.Name:
		return pallas.New(), nil
	default:
		return nil, errs.NewInvalidCurve("curve with name %s is not supported", name)
	}
}
