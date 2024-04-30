package require

import "reflect"

func IsNil(t any) bool {
	v := reflect.ValueOf(t)
	kind := v.Kind()
	// Must be one of these types to be nillable
	return (kind == reflect.Ptr || kind == reflect.Interface || kind == reflect.Slice ||
		kind == reflect.Map || kind == reflect.Chan || kind == reflect.Func || kind == reflect.UnsafePointer) &&
		v.IsNil()
}
