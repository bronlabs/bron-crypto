package curveutils

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

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
