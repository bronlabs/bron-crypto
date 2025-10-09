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
