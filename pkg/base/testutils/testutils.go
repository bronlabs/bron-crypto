package testutils

import (
	"reflect"
	"testing"

	"pgregory.net/rapid"
)

func CompileInvariant(t *testing.T, f any, args ...any) func(*rapid.T) {
	t.Helper()
	return func(t *rapid.T) {
		v := reflect.ValueOf(f)
		rargs := make([]reflect.Value, len(args)+1)
		rargs[0] = reflect.ValueOf(t)
		for i, a := range args {
			rargs[i+1] = reflect.ValueOf(a)
		}
		v.Call(rargs)
	}
}
