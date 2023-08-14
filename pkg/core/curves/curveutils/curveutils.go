package curveutils

import (
	"crypto/elliptic"
	"encoding/json"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/bls12381"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/pallas"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

func NewScalarFromJSON(data []byte) (curves.Scalar, error) {
	var m struct {
		Type string `json:"type"`
	}

	err := json.Unmarshal(data, &m)
	if err != nil {
		return nil, errs.WrapDeserializationFailed(err, "json unmarshal failed")
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
		return k256.K256Curve(), nil
	case p256.Name:
		return p256.NistP256Curve(), nil
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
