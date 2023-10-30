package base

import (
	"crypto/subtle"
	"math/bits"

	"golang.org/x/exp/constraints"
)

// Min returns the minimum of two elements.
func Min[T constraints.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}

// CeilDiv returns `ceil(numerator/denominator) for integer inputs. Equivalently,
// it returns `x`, the smallest integer that satisfies `(x*b) >= a`.
func CeilDiv(numerator, denominator int) int {
	return (numerator - 1 + denominator) / denominator
}

// ConstantTimeEq returns 1 if x == y and 0 otherwise. Based on the subtle package.
func ConstantTimeEq(x, y uint64) int {
	eqLow := subtle.ConstantTimeEq(int32(x), int32(y))
	eqHigh := subtle.ConstantTimeEq(int32(x>>32), int32(y>>32))
	return eqLow & eqHigh
}

// ConstantTimeGt returns 1 if x > y and 0 otherwise.
//
//   - If both x < 2^63 and y < 2^63, then y-x will have its high bit set only if x > y.
//   - If either x >= 2^63 or y >= 2^63 (but not both), then the result is the high bit of x.
//   - If both x >= 2^63 and y >= 2^63, then we can virtually subtract 2^63 from both,
//     and we are back to the first case. Since (y-2^63)-(x-2^63) = y-x, the direct subtraction is already fine.
func ConstantTimeGt(x, y uint64) int {
	z := y - x
	return int((z ^ ((x ^ y) & (x ^ z))) >> 63)
}

// ConstantTimeLeq returns 1 if x <= y and 0 otherwise.
func ConstantTimeLeq(x, y uint64) int {
	return 1 - ConstantTimeGt(y, x)
}

// FloorLog2 return floor(log2(x)).
func FloorLog2(x int) int {
	return 63 - bits.LeadingZeros64(uint64(x))
}

// CeilLog2 return ceil(log2(x)).
func CeilLog2(x int) int {
	return 64 - bits.LeadingZeros64(uint64(x)-1)
}
