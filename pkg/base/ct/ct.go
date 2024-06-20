package ct

import (
	"golang.org/x/exp/constraints"
)

func IsZero[I constraints.Unsigned](x I) uint64 {
	xx := uint64(x)
	return ((xx | -xx) >> 63) ^ 1
}

// Equal returns 1 if x == y and 0 otherwise. Based on the subtle package.
func Equal[I constraints.Unsigned](x, y I) uint64 {
	return IsZero(x ^ y)
}

// Greater returns 1 if x > y and 0 otherwise.
//
//   - If both x < 2^63 and y < 2^63, then y-x will have its high bit set only if x > y.
//   - If either x >= 2^63 or y >= 2^63 (but not both), then the result is the high bit of x.
//   - If both x >= 2^63 and y >= 2^63, then we can virtually subtract 2^63 from both,
//     and we are back to the first case. Since (y-2^63)-(x-2^63) = y-x, the direct subtraction is already fine.
func Greater[I constraints.Unsigned](x, y I) uint64 {
	xx := uint64(x)
	yy := uint64(y)
	zz := yy - xx
	return (zz ^ ((xx ^ yy) & (xx ^ zz))) >> 63
}

// Less returns 1 if x < y and 0 otherwise.
func Less[I constraints.Unsigned](x, y I) uint64 {
	return Greater(y, x)
}

// LessOrEqual returns 1 if x <= y and 0 otherwise.
func LessOrEqual[I constraints.Unsigned](x, y I) uint64 {
	return Greater(x, y) ^ 1
}

// GreaterOrEqual returns 1 if x >= y and 0 otherwise.
func GreaterOrEqual[I constraints.Unsigned](x, y I) uint64 {
	return Greater(y, x) ^ 1
}

// Select returns x0 if choice == 0 and x1 if choice == 1. Undefined for other values of choice.
func Select[I constraints.Unsigned](choice uint64, x0, x1 I) I {
	c := I(choice)
	return ((c - 1) & x0) | ((^(c - 1)) & x1)
}
