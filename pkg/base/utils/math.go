package utils

import (
	"encoding/binary"
	mathBits "math/bits"

	"golang.org/x/exp/constraints"
)

type math struct{}

var Math math

// BytesLeDecrement is a constant time algorithm for subtracting
// 1 from the byte array as if it were a low-endian big number.
// 0 is considered a wrap which resets to 0xFF.
func (math) BytesLeDecrement(b []byte) {
	carry := uint16(0)
	for i := range b {
		t := uint16(b[i]) + uint16(0x00ff) + carry
		b[i] = byte(t & 0xff)
		carry = t >> 8
	}
}

func (math) ToBytesLe32(i uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return b
}

// CeilDiv returns `ceil(numerator/denominator) for integer inputs. Equivalently,
// it returns `x`, the smallest integer that satisfies `(x*b) >= a`.
func (math) CeilDiv(numerator, denominator int) int {
	return (numerator - 1 + denominator) / denominator
}

// FloorLog2 return floor(log2(x)).
func (math) FloorLog2(x int) int {
	return 63 - mathBits.LeadingZeros64(uint64(x))
}

// CeilLog2 return ceil(log2(x)).
func (math) CeilLog2(x int) int {
	return 64 - mathBits.LeadingZeros64(uint64(x)-1)
}

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
