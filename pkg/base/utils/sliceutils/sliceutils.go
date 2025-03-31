package sliceutils

import "slices"

func Reversed[S ~[]T, T any](xs S) S {
	sx := make(S, len(xs))
	copy(sx, xs)
	slices.Reverse(sx)
	return sx
}

func Reverse[S ~[]T, T any](xs S) S {
	slices.Reverse(xs)
	return xs
}
