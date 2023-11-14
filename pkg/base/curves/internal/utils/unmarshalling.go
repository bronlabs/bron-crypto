package utils

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

func NewScalarFromMap(data map[string]any) (curves.Scalar, error) {
	curve, err := curveutils.GetCurveByName(data["type"].(string))
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "could not fetch curve")
	}
	value, err := json.Marshal(data)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "json marshal failed")
	}
	return internal.NewScalarFromJSON(curve.Scalar().SetBytes, value)
}

func NewPointFromMap(data map[string]any) (curves.Point, error) {
	curve, err := curveutils.GetCurveByName(data["type"].(string))
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "could not fetch curve")
	}
	value, err := json.Marshal(data)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "json marshal failed")
	}
	return internal.NewPointFromJSON(curve, value)
}

func UnmarshalCurveJSON(input []byte, a any) error {
	err := json.Unmarshal(input, a)
	var jsonErr *json.UnmarshalTypeError
	if !errors.As(err, &jsonErr) {
		return err
	}
	err = ReflectUnmarshalPoint(input, a, nil)
	if err != nil {
		return err
	}
	return nil
}

func ReflectUnmarshalPoint(input []byte, a any, ff *reflect.Value) error {
	var m map[string]any
	err := json.Unmarshal(input, &m)
	if err != nil {
		return err
	}
	var v reflect.Value
	if ff == nil {
		v = reflect.ValueOf(a).Elem()
	} else {
		v = ff.Elem()
	}
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		n := v.Type().Field(i).Name
		t := f.Type().String()
		switch t {
		case "curves.Point":
			err := setPointField(&f, n, m)
			if err != nil {
				return err
			}
		case "[]curves.Point":
			err := setArrayPointField(&f, n, m)
			if err != nil {
				return err
			}
		case "curves.Scalar":
			err := setScalarField(&f, n, m)
			if err != nil {
				return err
			}
		case "[]curves.Scalar":
			err := setArrayScalarField(&f, n, m)
			if err != nil {
				return err
			}
		default:
			if strings.Contains(t, ".") {
				err := setField(n, m, a, f)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func setField(n string, m map[string]any, a any, f reflect.Value) error {
	if m[n] != nil {
		mm, err := json.Marshal(m[n].(map[string]any))
		if err != nil {
			return err
		}
		err = ReflectUnmarshalPoint(mm, a, &f)
		if err != nil {
			return err
		}
	}
	return nil
}

func setArrayPointField(value *reflect.Value, n string, m map[string]any) error {
	if m[n] != nil {
		var points []curves.Point
		for _, p := range m[n].([]any) {
			pp, err := NewPointFromMap(p.(map[string]any))
			if err != nil {
				return err
			}
			points = append(points, pp)
		}
		value.Set(reflect.ValueOf(points))
	}
	return nil
}

func setPointField(f *reflect.Value, n string, m map[string]any) error {
	if m[n] != nil {
		p, err := NewPointFromMap(m[n].(map[string]any))
		if err != nil {
			return err
		}
		f.Set(reflect.ValueOf(p))
	}
	return nil
}

func setArrayScalarField(value *reflect.Value, n string, m map[string]any) error {
	if m[n] != nil {
		var points []curves.Scalar
		for _, p := range m[n].([]any) {
			pp, err := NewScalarFromMap(p.(map[string]any))
			if err != nil {
				return err
			}
			points = append(points, pp)
		}
		value.Set(reflect.ValueOf(points))
	}
	return nil
}

func setScalarField(f *reflect.Value, n string, m map[string]any) error {
	if m[n] != nil {
		p, err := NewScalarFromMap(m[n].(map[string]any))
		if err != nil {
			return err
		}
		f.Set(reflect.ValueOf(p))
	}
	return nil
}
