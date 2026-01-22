package sliceutils

import (
	"io"
	"slices"

	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
)

// MapOrError applies the function f to each element of the input slice in,.
func MapOrError[SIn ~[]TIn, TIn, TOut any](in SIn, f func(TIn) (TOut, error)) (out []TOut, err error) {
	out = make([]TOut, len(in))
	for i, in := range in {
		out[i], err = f(in)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// MapCast applies the function f to each element of the input slice in,
// casting the output slice to the desired type S.
func MapCast[S ~[]TOut, TOut any, SIn ~[]TIn, TIn any](in SIn, f func(TIn) TOut) S {
	return slices.Collect(iterutils.Map(slices.Values(in), f))
}

// Map applies the function f to each element of the input slice in,
// returning a slice of the output type.
func Map[TOut any, SIn ~[]TIn, TIn any](in SIn, f func(TIn) TOut) []TOut {
	return MapCast[[]TOut](in, f)
}

// Filter returns a new slice containing only the elements of xs that satisfy the predicate.
func Filter[S ~[]T, T any](xs S, predicate func(T) bool) S {
	return slices.Collect(iterutils.Filter(slices.Values(xs), predicate))
}

// Reduce reduces the slice xs to a single value by applying the binary function f cumulatively.
func Reduce[S ~[]T, T any](xs S, initial T, f func(T, T) T) T {
	return iterutils.Reduce(slices.Values(xs), initial, f)
}

// Repeat creates a slice of length n, filled with the value x.
func Repeat[S ~[]T, T any](x T, n int) S {
	out := make(S, n)
	for i := range n {
		out[i] = x
	}
	return out
}

// Reversed returns a new slice that is the reverse of the input slice.
func Reversed[S ~[]T, T any](xs S) S {
	sx := slices.Clone(xs)
	slices.Reverse(sx)
	return sx
}

// Reverse reverses the input slice in place and returns it.
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
		return nil, ErrArgumentIsNil.WithMessage("prng")
	}

	for i := uint64(len(xs)) - 1; i > 0; i-- {
		j, err := mathutils.RandomUint64Range(prng, i+1)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to sample random uint64 in range")
		}
		xs[j], xs[i] = xs[i], xs[j]
	}
	return xs, nil
}

// Shuffled returns a new slice that is a random permutation of the input slice.
func Shuffled[S ~[]T, T any](xs S, prng io.Reader) (S, error) {
	clone := make(S, len(xs))
	copy(clone, xs)
	return Shuffle(clone, prng)
}

// PadToLeft pads the input slice xs to the left with zero values to reach the desired padLength.
func PadToLeft[S ~[]T, T any](xs S, padLength int) S {
	if padLength < 0 {
		return xs
	}
	out := make(S, len(xs)+padLength)
	copy(out[padLength:], xs)
	return out
}

// PadToLeftWith pads the input slice xs to the left with the specified pad value to reach the desired padLength.
func PadToLeftWith[S ~[]T, T any](xs S, padLength int, pad T) S {
	out := PadToLeft(xs, padLength)
	for i := range padLength {
		out[i] = pad
	}
	return out
}

// PadToRight pads the input slice xs to the right with zero values to reach the desired padLength.
func PadToRight[S ~[]T, T any](xs S, padLength int) S {
	if padLength < 0 {
		return xs
	}
	out := make(S, len(xs)+padLength)
	copy(out[:len(xs)], xs)
	return out
}

// PadToRightWith pads the input slice xs to the right with the specified pad value to reach the desired padLength.
func PadToRightWith[S ~[]T, T any](xs S, padLength int, pad T) S {
	out := PadToRight(xs, padLength)
	for i := len(xs); i < len(out); i++ {
		out[i] = pad
	}
	return out
}

// Count returns the number of elements in xs that satisfy the predicate.
func Count[S ~[]T, T any](xs S, predicate func(T) bool) int {
	count := 0
	for _, x := range xs {
		if predicate(x) {
			count++
		}
	}
	return count
}

// CountUnique returns the number of unique elements in xs.
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

// CountUniqueFunc returns the number of unique elements in xs using the provided equality function.
func CountUniqueFunc[S ~[]T, T any](xs S, equal func(T, T) bool) int {
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

// Any returns true if any element in xs satisfies the predicate.
func Any[S ~[]T, T any](xs S, predicate func(T) bool) bool {
	return Count(xs, predicate) > 0
}

// All returns true if all elements in xs satisfy the predicate.
func All[S ~[]T, T any](xs S, predicate func(T) bool) bool {
	return Count(xs, predicate) == len(xs)
}

// IsAllUnique returns true if all elements in xs are unique.
func IsAllUnique[S ~[]T, T comparable](xs S) bool {
	return CountUnique(xs) == len(xs)
}

// IsAllUniqueFunc returns true if all elements in xs are unique using the provided equality function.
func IsAllUniqueFunc[S ~[]T, T any](xs S, equal func(T, T) bool) bool {
	return CountUniqueFunc(xs, equal) == len(xs)
}

// IsSubSet returns true if all elements of sub are present in sup.
func IsSubSet[SB, SP ~[]T, T comparable](sub SB, sup SP) bool {
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

// IsSubSetFunc returns true if all elements of sub are present in sup using the provided equality function.
func IsSubSetFunc[SB, SP ~[]T, T any](sub SB, sup SP, equal func(T, T) bool) bool {
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

// IsSuperSet returns true if ss contains all elements of s.
func IsSuperSet[T comparable](ss, s []T) bool {
	for _, si := range s {
		if !slices.Contains(ss, si) {
			return false
		}
	}

	return true
}

// ContainsFunc returns true if xs contains the element x using the provided equality function.
func ContainsFunc[S ~[]T, T any](xs S, x T, equal func(T, T) bool) bool {
	for _, y := range xs {
		if equal(x, y) {
			return true
		}
	}
	return false
}

// Fold reduces the slice rest to a single value by applying the binary function f cumulatively, starting with initial.
func Fold[T, U any](f func(acc U, x T) U, initial U, rest ...T) U {
	accumulator := func(acc U, x T) (U, error) { return f(acc, x), nil }
	out, err := FoldOrError(accumulator, initial, rest...)
	if err != nil {
		panic(errs.Wrap(err))
	}
	return out
}

// FoldOrError reduces the slice rest to a single value by applying the binary function f cumulatively, starting with initial.
func FoldOrError[T, U any](f func(acc U, x T) (U, error), initial U, rest ...T) (U, error) {
	if len(rest) == 0 {
		return initial, nil
	}
	out := initial
	var err error
	for _, x := range rest {
		out, err = f(out, x)
		if err != nil {
			return *new(U), errs.Wrap(err)
		}
	}
	return out, nil
}

// Fill fills the slice s with the value x.
func Fill[T any](s []T, x T) {
	for i := range s {
		s[i] = x
	}
}

var ErrArgumentIsNil = errs.New("argument is nil")
