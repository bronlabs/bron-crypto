package sliceutils

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/randutils"
	"io"
	"slices"
)

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

// Shuffle uses Fisher-Yates algorithm to produce a random permutation of the input.
// https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#The_modern_algorithmreally
// It ought not be called with relatively big len(xs) (e.g. that doesn't fit in 32 bits).
// Not only will it take a very long time, but with 2³¹! possible permutations,
// there's no way that any PRNG can have a big enough internal state to
// generate even a minuscule percentage of the possible permutations.
func Shuffle[S ~[]T, T any](xs S, prng io.Reader) (S, error) {
	if len(xs) == 0 {
		return xs, nil
	}
	if prng == nil {
		return nil, errs.NewIsNil("prng cannot be nil")
	}

	for i := uint64(len(xs)) - 1; i > 0; i-- {
		j, err := randutils.RandomUint64Range(prng, i+1)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "shuffle")
		}
		xs[j], xs[i] = xs[i], xs[j]
	}
	return xs, nil
}

func Shuffled[S ~[]T, T any](xs S, prng io.Reader) (S, error) {
	clone := make(S, len(xs))
	copy(clone, xs)
	return Shuffle(clone, prng)
}
