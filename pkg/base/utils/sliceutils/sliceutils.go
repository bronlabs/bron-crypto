package sliceutils

import (
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/randutils"
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

func MapCast[S ~[]TOut, TOut any, SIn ~[]TIn, TIn any](in SIn, f func(TIn) TOut) S {
	return slices.Collect(iterutils.Map(slices.Values(in), f))
}

func Map[TOut any, SIn ~[]TIn, TIn any](in SIn, f func(TIn) TOut) []TOut {
	return MapCast[[]TOut](in, f)
}

func Filter[S ~[]T, T any](xs S, predicate func(T) bool) S {
	return slices.Collect(iterutils.Filter(slices.Values(xs), predicate))
}

func Reduce[S ~[]T, T any](xs S, initial T, f func(T, T) T) T {
	return iterutils.Reduce(slices.Values(xs), initial, f)
}

func Repeat[S ~[]T, T any](x T, n int) S {
	out := make(S, n)
	for i := range n {
		out[i] = x
	}
	return out

}

func Reversed[S ~[]T, T any](xs S) S {
	sx := slices.Clone(xs)
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

func PadToLeft[S ~[]T, T any](xs S, padLength int) S {
	if padLength < 0 {
		return xs
	}
	out := make(S, len(xs)+padLength)
	copy(out[padLength:], xs)
	return out
}

func PadToLeftWith[S ~[]T, T any](xs S, padLength int, pad T) S {
	out := PadToLeft(xs, padLength)
	for i := range padLength {
		out[i] = pad
	}
	return out
}

func PadToRight[S ~[]T, T any](xs S, padLength int) S {
	if padLength < 0 {
		return xs
	}
	out := make(S, len(xs)+padLength)
	copy(out[:len(xs)], xs)
	return out
}

func PadToRightWith[S ~[]T, T any](xs S, padLength int, pad T) S {
	out := PadToRight(xs, padLength)
	for i := len(xs); i < len(out); i++ {
		out[i] = pad
	}
	return out
}

func Count[S ~[]T, T any](xs S, predicate func(T) bool) int {
	count := 0
	for _, x := range xs {
		if predicate(x) {
			count++
		}
	}
	return count
}

func CountUnique[S ~[]T, T comparable](xs S) int {
	seen := make(map[T]struct{})
	count := 0
	for _, x := range xs {
		if _, exists := seen[x]; !exists {
			seen[x] = struct{}{}
			count++
		}
	}
	return count
}

func CountUniqueFunc[S ~[]T, T any, K comparable](xs S, key func(T) K) int {
	seen := make(map[K]struct{})
	count := 0
	for _, x := range xs {
		k := key(x)
		if _, exists := seen[k]; !exists {
			seen[k] = struct{}{}
			count++
		}
	}
	return count
}

func CountUniqueEqualFunc[S ~[]T, T any](xs S, equal func(T, T) bool) int {
	seen := make([]T, 0, len(xs))
	count := 0
	for _, x := range xs {
		found := false
		for _, y := range seen {
			if equal(x, y) {
				found = true
				break
			}
		}
		if !found {
			seen = append(seen, x)
			count++
		}
	}
	return count
}

func Any[S ~[]T, T any](xs S, predicate func(T) bool) bool {
	return Count(xs, predicate) > 0
}

func All[S ~[]T, T any](xs S, predicate func(T) bool) bool {
	return Count(xs, predicate) == len(xs)
}

func IsUnique[S ~[]T, T comparable](xs S) bool {
	return CountUnique(xs) == len(xs)
}

func IsUniqueFunc[S ~[]T, T any, K comparable](xs S, key func(T) K) bool {
	return CountUniqueFunc(xs, key) == len(xs)
}

func IsSubList[SB, SP ~[]T, T comparable](sub SB, sup SP) bool {
	if len(sub) > len(sup) {
		return false
	}
	for _, x := range sub {
		found := false
		for _, y := range sup {
			if x == y {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func IsSubListFunc[SB, SP ~[]T, T any](sub SB, sup SP, equal func(T, T) bool) bool {
	if len(sub) > len(sup) {
		return false
	}
	for _, x := range sub {
		found := false
		for _, y := range sup {
			if equal(x, y) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func ContainsEqualFunc[S ~[]T, T any](xs S, x T, equal func(T, T) bool) bool {
	for _, y := range xs {
		if equal(x, y) {
			return true
		}
	}
	return false
}

func Fold[T, U any](f func(acc U, x T) U, initial U, rest ...T) U {
	accumulator := func(acc U, x T) (U, error) { return f(acc, x), nil }
	out, err := FoldOrError(accumulator, initial, rest...)
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
