package ct

import (
	"golang.org/x/exp/constraints"

	"github.com/copperexchange/krypton-primitives/pkg/base/utils/safecast"
)

// SliceEachEqual returns 1 if all values of s are equal to e and returns 0 otherwise. Based on the subtle package.
func SliceEachEqual[S ~[]I, I constraints.Unsigned](s S, e I) uint64 {
	v := I(0)
	for i := range s {
		v |= s[i] ^ e
	}
	return IsZero(v)
}

// SliceEqual returns 1 if x == y.
func SliceEqual[S ~[]I, I constraints.Unsigned](x, y S) uint64 {
	if len(x) != len(y) {
		panic("ct: slices have different lengths")
	}

	v := I(0)
	for i := range x {
		v |= x[i] ^ y[i]
	}
	return IsZero(v)
}

// SliceIsZero returns 1 if all values of s are equal to 0 and returns 0 otherwise. Based on the subtle package.
func SliceIsZero[S ~[]E, E constraints.Unsigned](s S) uint64 {
	v := E(0)
	for _, e := range s {
		v |= e
	}
	return IsZero(v)
}

// SliceSelect yields x1 if v == 1, x0 if v == 0.
// Its behaviour is undefined if v takes any other value.
func SliceSelect[S ~[]E, E constraints.Unsigned](choice uint64, dst, x0, x1 S) {
	if len(x0) != len(x1) || len(x0) != len(dst) {
		panic("ct: slices have different lengths")
	}

	for i := range dst {
		dst[i] = Select(choice, x0[i], x1[i])
	}
}

// SliceGreaterLE returns 1 if x > y and 0 otherwise,
// where the slice is little-endian limb-like representation.
//
//nolint:gosec // disable G115
func SliceGreaterLE[S ~[]E, E constraints.Unsigned](x, y S) uint64 {
	return IsZero(uint64(SliceCmpLE(x, y) ^ 1))
}

// SliceCmpLE returns 1 if x > y, 0 if x == y, -1 if x < y,
// where the slice is little-endian limb-like representation.
func SliceCmpLE[S ~[]E, E constraints.Unsigned](x, y S) int64 {
	if len(x) != len(y) {
		panic("ct: slices have different lengths")
	}

	gt := uint64(0)
	lt := uint64(0)
	for i := len(x) - 1; i >= 0; i-- {
		gt |= Greater(x[i], y[i]) & ^lt
		lt |= Less(x[i], y[i]) & ^gt
	}
	return safecast.MustToInt64(gt) - safecast.MustToInt64(lt)
}
