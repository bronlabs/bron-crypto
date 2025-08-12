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

// SliceSelect yields x1 if choice == 1, x0 if choice == 0.
// Its behaviour is undefined if choice takes any other value.
func SliceSelect[S ~[]E, E constraints.Unsigned](choice Choice, x0, x1 S) S {
	if len(x0) != len(x1) {
		panic("ct: slices have different lengths")
	}

	out := make(S, len(x0))
	for i := range out {
		out[i] = Select(choice, x0[i], x1[i])
	}
	return out
}

// BytesCompare is the constant-time counterpart of bytes.Compare.
//
// The comparison is lexicographic: the first differing byte determines
// the ordering; if one slice is a prefix of the other, the shorter slice
// is considered smaller.
func BytesCompare(x, y []byte) (lt, eq, gt Bool) {
	maxLen := len(x)
	if len(y) > maxLen {
		maxLen = len(y)
	}

	var done Choice // 1 after the first difference
	for i := 0; i < maxLen; i++ {
		bx := ReturnByteIfTrue(i < len(x), x[len(x)-maxLen+i])
		by := ReturnByteIfTrue(i < len(y), y[len(y)-maxLen+i])

		less := Less(bx, by)    // 1 if bx < by
		greater := Less(by, bx) // 1 if bx > by

		lt |= Bool(less & (done ^ 1))
		gt |= Bool(greater & (done ^ 1))
		done |= less | greater
	}

	eq = Bool(done ^ 1) // 1 iff no difference
	return
}

func ReturnByteIfTrue(cond bool, b byte) byte {
	mask := Choice(0)
	if cond {
		mask = 1
	}
	return Select(mask, 0, b)
}
