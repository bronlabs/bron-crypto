package cardinal

import (
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base"
)

var i Cardinal = infinite{}

func Infinite() Cardinal {
	return i
}

// infinite represents an infinite cardinal number.
type infinite struct{}

// IsLessThanOrEqual checks if the infinite cardinal is less than or equal to another cardinal.
// It will be equal only to another Infinite cardinal.
func (i infinite) IsLessThanOrEqual(other Cardinal) bool {
	_, otherIsInfinite := other.(infinite)
	return otherIsInfinite
}

// Clone returns a copy of the infinite cardinal.
func (i infinite) Clone() Cardinal {
	return i
}

// HashCode returns the hash code of the infinite cardinal.
func (i infinite) HashCode() base.HashCode {
	return base.DeriveHashCode([]byte("InfiniteCardinal"))
}

// Equal checks if the infinite cardinal is equal to another cardinal.
// It will be equal only to another Infinite cardinal.
func (i infinite) Equal(other Cardinal) bool {
	_, otherIsInfinite := other.(infinite)
	return otherIsInfinite
}

// Bytes panics as Bytes is not defined for Infinite cardinal.
func (i infinite) Bytes() []byte {
	panic("Bytes() not supported for Infinite cardinal")
}

// BytesBE panics as BytesBE is not defined for Infinite cardinal.
func (i infinite) BytesBE() []byte {
	panic("BytesBE() not supported for Infinite cardinal")
}

// String returns the string representation of the infinite cardinal.
func (i infinite) String() string {
	return "InfiniteCardinal"
}

// Add returns Infinite cardinal when adding with any other cardinal.
func (i infinite) Add(other Cardinal) Cardinal {
	return i
}

// Mul returns Infinite cardinal when multiplying with any other cardinal.
func (i infinite) Mul(other Cardinal) Cardinal {
	return i
}

// Big panics as Big is not defined for Infinite cardinal.
func (i infinite) Big() *big.Int {
	panic("Big() not supported for Infinite cardinal")
}

// Uint64 panics as Uint64 is not defined for Infinite cardinal.
func (i infinite) Uint64() uint64 {
	panic("Uint64() not supported for Infinite cardinal")
}

// IsZero always returns false for Infinite cardinal.
func (i infinite) IsZero() bool {
	return false
}

// IsFinite always returns false for Infinite cardinal.
func (i infinite) IsFinite() bool {
	return false
}

// IsUnknown always returns false for Infinite cardinal.
func (i infinite) IsUnknown() bool {
	return false
}

// IsProbablyPrime panics as IsProbablyPrime is not defined for Infinite cardinal.
func (i infinite) IsProbablyPrime() bool {
	panic("IsProbablyPrime() not supported for Infinite cardinal")
}

// BitLen panics as BitLen is not defined for Infinite cardinal.
func (i infinite) BitLen() int {
	panic("BitLen() not supported for Infinite cardinal")
}
