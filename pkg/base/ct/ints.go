package ct

import (
	"reflect"

	"golang.org/x/exp/constraints"
)

// TODO: Review Mateusz

func IsZero[I constraints.Integer](x I) Choice {
	// Handle all integer sizes properly
	xx := uint64(x)
	// For unsigned types, -xx wraps around; for signed types it negates
	// The bitwise OR with its negation sets the MSB if x != 0
	return Choice(((xx | -xx) >> 63) ^ 1)
}

// Equal returns 1 if x == y and 0 otherwise. Based on the subtle package.
func Equal[I constraints.Integer](x, y I) Choice {
	return IsZero(x ^ y)
}

// Greater returns 1 iff x > y, using the natural order of I.
func Greater[I constraints.Integer](x, y I) Choice {
	if isSigned[I]() {
		return LessI64(int64(y), int64(x))
	}
	return LessU64(uint64(y), uint64(x))
}

// Less returns 1 iff x < y.
func Less[I constraints.Integer](x, y I) Choice {
	return Greater(y, x)
}

// LessOrEqual returns 1 iff x <= y.
func LessOrEqual[I constraints.Integer](x, y I) Choice {
	return Greater(x, y) ^ 1
}

// GreaterOrEqual returns 1 iff x >= y.
func GreaterOrEqual[I constraints.Integer](x, y I) Choice {
	return Less(x, y) ^ 1
}
func CompareInteger[I constraints.Integer](x, y I) (gt, eq, lt Bool) {
	// Equal: 1 if x == y, else 0
	eq = Equal(x, y)

	// Greater: 1 if x > y, else 0
	gt = Greater(x, y)

	// Less: 1 if x < y, else 0
	lt = Less(x, y)
	return
}

// SelectInteger returns x0 if choice == 0 and x1 if choice == 1. Undefined for other values of choice.
// It supports both signed and unsigned integer types.
func SelectInteger[I constraints.Integer](choice Choice, x0, x1 I) I {
	mask := I(-int64(choice)) // 0 if choice == 0, -1 (all bits 1) if choice == 1
	return (x0 &^ mask) | (x1 & mask)
}

// Min returns the smaller of a and b in constant time.
func Min[T constraints.Integer](a, b T) T {
	// Select(choice, x0, x1): if choice=0 return x0, if choice=1 return x1
	// Less(a, b) returns 1 if a < b, 0 otherwise
	// If a < b (Less=1), we want a
	// If a >= b (Less=0), we want b
	return SelectInteger(Less(a, b), b, a)
}

// Max returns the larger of a and b in constant time.
func Max[T constraints.Integer](a, b T) T {
	// Select(choice, x0, x1): if choice=0 return x0, if choice=1 return x1
	// Greater(a, b) returns 1 if a > b, 0 otherwise
	// If a > b (Greater=1), we want a
	// If a <= b (Greater=0), we want b
	return SelectInteger(Greater(a, b), b, a)
}

// Isqrt64 computes floor(sqrt(n)) for a 64-bit n in constant time.
// Uses binary search with 32 iterations to ensure constant time execution.
func Isqrt64(n uint64) uint64 {
	var result uint64 = 0
	var bit uint64 = 1 << 31 // Start with highest bit for 32-bit result

	// Binary search: test each bit from high to low
	for range 32 {
		temp := result + bit
		square := temp * temp
		// Keep the bit if temp^2 <= n (no overflow for temp < 2^32)
		le := LessOrEqual(square, n)
		result = SelectInteger(le, result, temp)
		bit >>= 1
	}
	return result
}

func isSigned[I constraints.Integer]() bool {
	var zero I
	switch reflect.TypeOf(zero).Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return false
	default:
		panic("not an integer type")
	}
}

func LessU64(x, y uint64) Choice {
	// Use borrow: x < y iff x - y borrows (sets MSB)
	// But we need to check for borrow, not just MSB of result
	// x < y iff (x ^ ((x ^ y) | ((x - y) ^ y))) has MSB set
	return Choice((x ^ ((x ^ y) | ((x - y) ^ y))) >> 63)
}

func LessI64(x, y int64) Choice {
	// Convert to unsigned by flipping sign bit, then compare as unsigned
	ux := uint64(x) ^ (1 << 63)
	uy := uint64(y) ^ (1 << 63)
	return LessU64(ux, uy)
}
