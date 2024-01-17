package curveutils

import (
	"crypto/elliptic"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curve25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
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

// ToGoEllipticCurve returns the equivalent of this curve as the go interface `elliptic.Curve`.
func ToGoEllipticCurve(c curves.Curve) (elliptic.Curve, error) {
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

func NewPointFromJSON(input []byte) (curves.Point, error) {
	name, data, err := impl.ParseJSON(input)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not get curve name from json")
	}
	curve, err := GetCurveByName(name)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get curve corresponding to name '%s'", name)
	}
	point, err := curve.Point().FromAffineCompressed(data)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not deserialize json into point")
	}
	return point, nil
}

func NewPointFromBinary(input []byte) (curves.Point, error) {
	name, data, err := impl.ParseBinary(input)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not get curve name from binary")
	}
	curve, err := GetCurveByName(name)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get curve corresponding to name '%s'", name)
	}
	point, err := curve.Point().FromAffineCompressed(data)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not deserialize binary into point")
	}
	return point, nil
}

func NewScalarFromJSON(input []byte) (curves.Scalar, error) {
	name, data, err := impl.ParseJSON(input)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not get curve name from json")
	}
	curve, err := GetCurveByName(name)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get curve corresponding to name '%s'", name)
	}
	scalar, err := curve.ScalarField().Element().SetBytes(data)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not deserialize json into scalar")
	}
	return scalar, nil
}

func NewScalarFromBinary(input []byte) (curves.Scalar, error) {
	name, data, err := impl.ParseBinary(input)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not get curve name from binary")
	}
	curve, err := GetCurveByName(name)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get curve corresponding to name '%s'", name)
	}
	scalar, err := curve.ScalarField().Element().SetBytes(data)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not deserialize binary into scalar")
	}
	return scalar, nil
}

func NewBaseFieldElementFromJSON(input []byte) (curves.BaseFieldElement, error) {
	name, data, err := impl.ParseJSON(input)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not get curve name from json")
	}
	curve, err := GetCurveByName(name)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get curve corresponding to name '%s'", name)
	}
	element, err := curve.BaseField().Element().SetBytes(data)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not deserialize json into scalar")
	}
	return element, nil
}

func NewBaseFieldElementFromBinary(input []byte) (curves.BaseFieldElement, error) {
	name, data, err := impl.ParseBinary(input)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not get curve name from binary")
	}
	curve, err := GetCurveByName(name)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get curve corresponding to name '%s'", name)
	}
	element, err := curve.BaseField().Element().SetBytes(data)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not deserialize binary into scalar")
	}
	return element, nil
}
