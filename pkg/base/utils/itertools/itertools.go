package itertools

import "github.com/copperexchange/krypton-primitives/pkg/base/errs"

func Contains[T any](xs []T, y T, isEqual func(a, b T) bool) bool {
	for _, x := range xs {
		if eq(isEqual, x, y) {
			return true
		}
	}
	return false
}

func ContainsComparable[T comparable](xs []T, y T) bool {
	_, exists := NativeHashSet(xs)[y]
	return exists
}

func Unique[T any](xs []T, isEqual func(a, b T) bool) []T {
	out := []T{}
OUTER:
	for i, xi := range xs {
		for j, xj := range xs {
			if i == j {
				continue
			}
			if eq(isEqual, xi, xj) {
				continue OUTER
			}
		}
		out = append(out, xi)
	}
	return out
}

func UniqueComparable[T comparable](xs []T) []T {
	h := NativeHashSet(xs)
	out := make([]T, len(h))
	i := 0
	for x := range h {
		out[i] = x
		i++
	}
	return out
}

func Filter[T any](xs []T, shouldKeep func(T) bool) []T {
	out := []T{}
	for _, x := range xs {
		if shouldKeep(x) {
			out = append(out, x)
		}
	}
	return out
}

func Product[T any](xs, ys []T) []T {
	out := make([]T, len(xs)+len(ys))
	for i, x := range xs {
		out[i] = x
	}
	for j, y := range ys {
		out[len(xs)+j] = y
	}
	return out
}

func ZipSmallest[T any](xs, ys []T) [][2]T {
	length := len(xs)
	if len(ys) < len(xs) {
		length = len(ys)
	}
	out := make([][2]T, length)
	for i := range length {
		out[i] = [2]T{xs[i], ys[i]}
	}
	return out
}

func Map[T, U any](xs []T, f func(x T) U) []U {
	out := make([]U, len(xs))
	for i, x := range xs {
		out[i] = f(x)
	}
	return out
}

func MapOrError[T, U any](xs []T, f func(x T) (U, error)) ([]U, error) {
	var err error
	out := make([]U, len(xs))
	for i, x := range xs {
		out[i], err = f(x)
		if err != nil {
			return nil, errs.WrapFailed(err, "couldn't map")
		}
	}
	return out, nil
}

func Reverse[T any](xs []T) []T {
	sx := make([]T, len(xs))
	for i, j := 0, len(xs)-1; j >= 0; i, j = i+1, j-1 {
		sx[i] = xs[j]
	}
	return sx
}

func Fold[T, U any](f func(acc U, x T) U, initial U, rest ...T) U {
	accumulator := func(acc U, x T) (U, error) { return f(acc, x), nil }
	out, err := FoldOrError(accumulator, initial, rest...)
	if err != nil {
		panic(errs.WrapFailed(err, "should not have had any errors"))
	}
	return out
}

func FoldRight[T, U any](f func(acc U, x T) U, initial U, rest ...T) U {
	accumulator := func(acc U, x T) (U, error) { return f(acc, x), nil }
	out, err := FoldRightOrError(accumulator, initial, rest...)
	if err != nil {
		panic(errs.WrapFailed(err, "should not have had any errors"))
	}
	return out
}

func FoldOrError[T, U any](f func(acc U, x T) (U, error), initial U, rest ...T) (U, error) {
	if len(rest) == 0 {
		return initial, nil
	}
	out := initial
	var err error
	for i, x := range rest {
		out, err = f(out, x)
		if err != nil {
			return *new(U), errs.WrapFailed(err, "could not fold at iteration %d", i)
		}
	}
	return out, nil
}

func FoldRightOrError[T, U any](f func(acc U, x T) (U, error), initial U, rest ...T) (U, error) {
	if len(rest) == 0 {
		return initial, nil
	}
	var err error
	out := initial
	for i := len(rest) - 1; i >= 0; i-- {
		out, err = f(out, rest[i])
		if err != nil {
			return *new(U), errs.WrapFailed(err, "could not right fold at iteration %d", i)
		}
	}
	return out, nil
}
