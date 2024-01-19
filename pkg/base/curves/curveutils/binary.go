package curveutils

import (
	"reflect"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

func MarshalPointToBinary(point curves.Point) ([]byte, error) {
	return marshalToBinaryWithUnexposedBinaryMarshaller(point, reflect.TypeOf((*curves.Point)(nil)))
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

func MarshalScalarToBinary(scalar curves.Scalar) ([]byte, error) {
	return marshalToBinaryWithUnexposedBinaryMarshaller(scalar, reflect.TypeOf((*curves.Scalar)(nil)))
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

func MarshalBaseFieldElementToBinary(element curves.BaseFieldElement) ([]byte, error) {
	return marshalToBinaryWithUnexposedBinaryMarshaller(element, reflect.TypeOf((*curves.BaseFieldElement)(nil)))
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

func marshalToBinaryWithUnexposedBinaryMarshaller(x any, iType reflect.Type) ([]byte, error) {
	v := reflect.ValueOf(x)

	// Check for nil interface
	if v.Kind() == reflect.Ptr && v.IsNil() {
		return nil, errs.NewIsNil("nil pointer passed")
	}

	// Check if the input implements the correct type ie x is scalar if iType is scalar etc.
	if !v.Type().Implements(iType.Elem()) {
		return nil, errs.NewInvalidType("inputs type mismatch")
	}

	// extract the underlying value
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if !v.IsValid() {
		return nil, errs.NewFailed("value is invalid")
	}
	if v.Kind() == reflect.Ptr {
		return nil, errs.NewFailed("pointer to pointer")
	}

	// value to a pointer to call the method from the underlying struct
	vPtr := reflect.New(v.Type())
	vPtr.Elem().Set(v)

	marshalMethod := vPtr.MethodByName("MarshalBinary")
	if !marshalMethod.IsValid() {
		return nil, errs.NewMissing("MarshalBinary method is missing")
	}

	results := marshalMethod.Call(nil)
	if len(results) != 2 {
		return nil, errs.NewInvalidType("type signature mismatch. returned %d results", len(results))
	}

	if !results[1].IsNil() {
		return nil, errs.WrapFailed(results[1].Interface().(error), "marshal binary error")
	}
	data, ok := results[0].Interface().([]byte)
	if !ok {
		return nil, errs.NewInvalidType("type of the result is not []byte")
	}
	return data, nil
}
