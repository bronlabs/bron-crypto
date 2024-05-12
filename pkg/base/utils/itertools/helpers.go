package itertools

import "reflect"

func NativeHashSet[T comparable](xs []T) map[T]any {
	h := map[T]any{}
	for _, x := range xs {
		h[x] = true
	}
	return h
}

func IsComparable(x any) bool {
	return reflect.ValueOf(x).Comparable()
}

func eq[T any](f func(a, b T) bool, x, y T) bool {
	if f == nil {
		return reflect.DeepEqual(x, y)
	}
	return f(x, y)
}
