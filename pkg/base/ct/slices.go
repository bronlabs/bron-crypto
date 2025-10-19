package ct

import (
	"golang.org/x/exp/constraints"
)

// SliceEachEqual returns 1 if all values of s are equal to e and returns 0 otherwise. Based on the subtle package.
func SliceEachEqual[S ~[]I, I constraints.Integer](s S, e I) Choice {
	v := I(0)
	for i := range s {
		v |= s[i] ^ e
	}
	return IsZero(v)
}

// SliceEqual returns 1 if x == y.
func SliceEqual[S ~[]I, I constraints.Integer](x, y S) Choice {
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
func SliceIsZero[S ~[]E, E constraints.Integer](s S) Choice {
	v := E(0)
	for _, e := range s {
		v |= e
	}
	return IsZero(v)
}

// CSelectInts yields x1 if choice == 1, x0 if choice == 0.
// Its behaviour is undefined if choice takes any other value.
func CSelectInts[S ~[]E, E constraints.Integer](choice Choice, x0, x1 S) S {
	if len(x0) != len(x1) {
		panic("ct: slices have different lengths")
	}

	out := make(S, len(x0))
	for i := range out {
		out[i] = CSelectInt(choice, x0[i], x1[i])
	}
	return out
}

// CMOVInts does: dst[i] = src[i] iff yes==1; otherwise dst[i] unchanged.
// Panics if lengths differ. Branch-free per element.
func CMOVInts[S ~[]I, I constraints.Integer](dst, src S, yes Choice) {
	if len(dst) != len(src) {
		panic("ct: slices have different lengths")
	}
	mask := I(-int64(yes & 1))
	for i := range dst {
		dst[i] = (dst[i] &^ mask) | (src[i] & mask)
	}
}

// CSwapInts swaps x[i] and y[i] iff yes==1; otherwise unchanged.
// Panics if lengths differ. Branch-free per element.
func CSwapInts[S ~[]I, I constraints.Integer](x, y S, yes Choice) {
	if len(x) != len(y) {
		panic("ct: slices have different lengths")
	}
	mask := I(-int64(yes & 1))
	for i := range x {
		d := (x[i] ^ y[i]) & mask
		x[i] ^= d
		y[i] ^= d
	}
}
