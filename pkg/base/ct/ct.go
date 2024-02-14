package ct

import (
	"crypto/subtle"

	"golang.org/x/exp/constraints"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
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

// ConstantTimeSelect returns x if v == 1 and y if v == 0. Its behaviour is undefined if v takes any other value.
func ConstantTimeSelect(v, x, y uint64) uint64 {
	return ^(v-1)&x | (v-1)&y
}

// ConstantTimeSelect returns x if v == 1 and y if v == 0. Its behaviour is undefined if v takes any other value.
func SelectScalar[T constraints.Integer](v T, x, y curves.Scalar) curves.Scalar {
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	subtle.ConstantTimeCopy(int(v), yBytes, xBytes)
	z, err := y.SetBytes(yBytes)
	if err != nil {
		panic("scalar.SetBytes(scalar.Bytes()) should never fail")
	}
	return z
}

// IsAllZero returns 1 if all values of x are zero and returns 0 otherwise. Based on the subtle package.
func IsAllZero(x []byte) int {
	zero := make([]byte, len(x))
	return subtle.ConstantTimeCompare(x, zero)
}
