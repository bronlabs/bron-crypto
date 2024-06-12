package ct

import (
	"crypto/subtle"

	"golang.org/x/exp/constraints"
)

// Equal returns 1 if x == y and 0 otherwise. Based on the subtle package.
func Equal(x, y uint64) int {
	eqLow := subtle.ConstantTimeEq(int32(x), int32(y))
	eqHigh := subtle.ConstantTimeEq(int32(x>>32), int32(y>>32))
	return eqLow & eqHigh
}

// GreaterThan returns 1 if x > y and 0 otherwise.
//
//   - If both x < 2^63 and y < 2^63, then y-x will have its high bit set only if x > y.
//   - If either x >= 2^63 or y >= 2^63 (but not both), then the result is the high bit of x.
//   - If both x >= 2^63 and y >= 2^63, then we can virtually subtract 2^63 from both,
//     and we are back to the first case. Since (y-2^63)-(x-2^63) = y-x, the direct subtraction is already fine.
func GreaterThan(x, y uint64) int {
	z := y - x
	return int((z ^ ((x ^ y) & (x ^ z))) >> 63)
}

// LessThanOrEqual returns 1 if x <= y and 0 otherwise.
func LessThanOrEqual(x, y uint64) int {
	return 1 - GreaterThan(y, x)
}

// Select returns x0 if choice == 0 and x1 if choice == 1. Undefined for other values of choice.
func Select(choice, x0, x1 uint64) uint64 {
	return (choice-1)&x0 | ^(choice-1)&x1
}

// IsAllEqual returns 1 if all values of s are equal to e and returns 0 otherwise. Based on the subtle package.
func IsAllEqual[S ~[]E, E constraints.Integer](s S, e E) int {
	var v E
	for i := range s {
		v |= s[i] ^ e
	}
	return Equal(uint64(v), 0)
}

// IsAllEqual returns 1 if all values of s are equal to 0 and returns 0 otherwise. Based on the subtle package.
func IsAllZeros[S ~[]E, E constraints.Integer](s S) int {
	return IsAllEqual(s, 0)
}

// SelectSlice yields x1 if v == 1, x0 if v == 0. Its behaviour is undefined if
// v takes any other value. Based on subtle.ConstantTimeCopy.
func SelectSlice(v int, dst, x0, x1 []byte) {
	if len(x0) != len(x1) || len(x0) != len(dst) {
		panic("subtle: slices have different lengths")
	}
	xmask := byte(v - 1)
	ymask := byte(^(v - 1))
	for i := 0; i < len(x0); i++ {
		dst[i] = x0[i]&xmask | x1[i]&ymask
	}
}
