package utils

import (
	"encoding/hex"
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

// Max returns the minimum of two elements.
func Max[T constraints.Ordered](a, b T) T {
	if a > b {
		return a
	}
	return b
}

// BoolTo casts a bool to any integer type.
func BoolTo[T constraints.Integer](b bool) T {
	if b {
		return 1
	}
	return 0
}

// CeilDiv returns `ceil(numerator/denominator) for integer inputs. Equivalently,
// it returns `x`, the smallest integer that satisfies `(x*b) >= a`.
func CeilDiv(numerator, denominator int) int {
	return (numerator - 1 + denominator) / denominator
}

// FloorLog2 return floor(log2(x)).
func FloorLog2(x int) int {
	return 63 - bits.LeadingZeros64(uint64(x))
}

// CeilLog2 return ceil(log2(x)).
func CeilLog2(x int) int {
	return 64 - bits.LeadingZeros64(uint64(x)-1)
}

// DecodeString decodes a hex string into a byte slice. It panics if the string is not a valid hex string.
func DecodeString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
