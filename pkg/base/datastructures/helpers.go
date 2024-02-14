package datastructures

import "reflect"

// The following chicanery is needed because we can neither union `comparable` and `Hashable` nor we can do a type switch on a type parameter to check if it implements some other type.

func IsHashable[T any]() bool {
	value := new(T)
	valueType := reflect.TypeOf(value)

	hashCodeMethod, hashCodeExists := valueType.MethodByName("HashCode")
	if !hashCodeExists || hashCodeMethod.Type.NumIn() != 1 || hashCodeMethod.Type.NumOut() != 1 || hashCodeMethod.Type.Out(0).Kind() != reflect.Uint64 {
		return false
	}

	equalMethod, equalExists := valueType.MethodByName("Equal")
	if !equalExists || equalMethod.Type.NumIn() != 2 || equalMethod.Type.NumOut() != 1 || equalMethod.Type.Out(0).Kind() != reflect.Bool ||
		!equalMethod.Type.In(1).AssignableTo(valueType) {

		return false
	}

	return true
}

// https://go.dev/ref/spec#Comparison_operators
// A type is strictly comparable if it is comparable and not an interface type nor composed of interface types. Specifically:

// Boolean, numeric, string, pointer, and channel types are strictly comparable.
// Struct types are strictly comparable if all their field types are strictly comparable.
// Array types are strictly comparable if their array element types are strictly comparable.
// Type parameters are strictly comparable if all types in their type set are strictly comparable.
//
// The function returns true for all strictly comparable types, except type parameters, because reflection on them is not supported .... sigh.
func IsStrictlyComparable[T any]() bool {
	return isStrictlyComparable(reflect.TypeOf(new(T)))
}

func isStrictlyComparable(t reflect.Type) bool {
	switch t.Kind() { //nolint:exhaustive // no need to check irrelevant kinds.
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128,
		reflect.String,
		reflect.Uintptr, reflect.UnsafePointer, reflect.Ptr,
		reflect.Chan:
		return true
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if !isStrictlyComparable(t.Field(i).Type) {
				return false
			}
		}
		return true
	case reflect.Array:
		return isStrictlyComparable(t.Elem())
	// case type parameter not supported
	default:
		return false
	}
}
