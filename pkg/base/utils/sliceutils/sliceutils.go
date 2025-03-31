package sliceutils

import "slices"

func MapErrFunc[SIn ~[]TIn, TIn, TOut any](in SIn, f func(TIn) (TOut, error)) (out []TOut, err error) {
	out = make([]TOut, len(in))
	for i, in := range in {
		out[i], err = f(in)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

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
