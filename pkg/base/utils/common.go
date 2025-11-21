package utils

import (
	"reflect"

	"golang.org/x/exp/constraints"
)

// BoolTo casts a bool to any integer type.
func BoolTo[T constraints.Integer](b bool) T {
	if b {
		return 1
	}
	return 0
}

// IsNil returns true if the given value is nil.
func IsNil[T any](v T) bool {
	val := reflect.ValueOf(v)
	if !val.IsValid() {
		return true
	}
	kind := val.Kind()
	return (kind == reflect.Ptr || kind == reflect.Interface) && val.IsNil()
}

// LeadingZeroBytes returns the count of 0x00 prefix bytes.
func LeadingZeroBytes(b []byte) int {
	i := 0
	for i < len(b) && b[i] == 0 {
		i++
	}
	return i
}

// ImplementsX checks if the given value v implements the interface X.
func ImplementsX[X, T any](v T) (X, bool) {
	// try value
	if x, ok := any(v).(X); ok {
		return x, true
	}
	// try pointer (covers methods with pointer receivers)
	vv := v
	if x, ok := any(&vv).(X); ok {
		return x, true
	}
	return *new(X), false
}

// Binomial computes the binomial coefficient "n choose k".
func Binomial(n, k int) int {
	// (n,k) = (n, n-k)
	if k > n/2 {
		k = n - k
	}
	b := 1
	for i := 1; i <= k; i++ {
		b = (n - k + i) * b / i
	}
	return b
}
