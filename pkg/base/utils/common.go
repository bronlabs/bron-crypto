package utils

import (
	"math/bits"
	"reflect"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"golang.org/x/exp/constraints"
)

func ParseOrderingFromSign[T constraints.Signed](x T) base.PartialOrdering {
	if x == 1 {
		return base.GreaterThan
	}
	if x == 0 {
		return base.Equal
	}
	if x == -1 {
		return base.LessThan
	}
	return base.Incomparable
}

func ParseOrderingFromMasks[F constraints.Integer](gt, eq, lt F) base.PartialOrdering {
	if gt != 0 {
		return base.GreaterThan
	}
	if eq != 0 {
		return base.Equal
	}
	if lt != 0 {
		return base.LessThan
	}
	return base.Incomparable
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

func IsNil[T any](v T) bool {
	val := reflect.ValueOf(v)
	kind := val.Kind()
	return (kind == reflect.Ptr || kind == reflect.Interface) && val.IsNil()
}

// LeadingZeroBytes returns the count of 0x00 prefix bytes.
func LeadingZeroBytes(b []byte) int {
	i := 0
	for i < len(b) && b[i] == 0 {
		i++
	}
	return i
}
