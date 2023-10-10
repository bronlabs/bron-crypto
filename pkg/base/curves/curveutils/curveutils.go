package curveutils

import (
	"crypto/elliptic"
	"encoding/json"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

func NewScalarFromJSON(data []byte) (curves.Scalar, error) {
	var m struct {
		Type string `json:"type"`
	}

	err := json.Unmarshal(data, &m)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "json unmarshal failed")
	}
	curve, err := GetCurveByName(m.Type)
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "could not fetch curve")
	}
	return internal.NewScalarFromJSON(curve.Scalar().SetBytes, data)
}

// ToEllipticCurve returns the equivalent of this curve as the go interface `elliptic.Curve`.
func ToEllipticCurve(c curves.Curve) (elliptic.Curve, error) {
	err := errs.NewInvalidCurve("can't convert %s", c.Name())
	switch c.Name() {
	case k256.Name:
		return k256.NewElliptic(), nil
	case p256.Name:
		return elliptic.P256(), nil
	default:
		return nil, err
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

func AllOnTheSameCurve(xs []curves.Scalar, Xs []curves.Point) bool {
	var curve curves.Curve
	if len(xs) != 0 {
		for i := 0; i < len(xs); i++ {
			if xs[0].CurveName() != xs[i].CurveName() {
				return false
			}
		}
		curve = xs[0].Curve()
	}
	if len(Xs) != 0 {
		for i := 0; i < len(Xs); i++ {
			if Xs[0].CurveName() != Xs[i].CurveName() {
				return false
			}
		}
		if Xs[0].CurveName() != curve.Name() {
			return false
		}
	}
	return true
}
