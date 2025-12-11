package cardinal

import (
	"math"
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base"
)

// IsInfinite returns true if the cardinal is infinite.
func IsInfinite(c Cardinal) bool {
	return !c.IsUnknown() && !c.IsFinite()
}

// Infinite represents an infinite cardinal number.
type Infinite struct{}

// IsLessThanOrEqual checks if the infinite cardinal is less than or equal to another cardinal.
// It will be equal only to another Infinite cardinal.
func (i Infinite) IsLessThanOrEqual(other Cardinal) bool {
	_, otherIsInfinite := other.(Infinite)
	return otherIsInfinite
}

// Clone returns a copy of the infinite cardinal.
func (i Infinite) Clone() Cardinal {
	return Infinite{}
}

// HashCode returns the hash code of the infinite cardinal.
func (i Infinite) HashCode() base.HashCode {
	return base.DeriveHashCode([]byte("InfiniteCardinal"))
}

// Equal checks if the infinite cardinal is equal to another cardinal.
// It will be equal only to another Infinite cardinal.
func (i Infinite) Equal(other Cardinal) bool {
	_, otherIsInfinite := other.(Infinite)
	return otherIsInfinite
}

// Bytes returns nil for the infinite cardinal.
func (i Infinite) Bytes() []byte {
	return nil
}

// BytesBE returns nil for the infinite cardinal.
func (i Infinite) BytesBE() []byte {
	return nil
}

// String returns the string representation of the infinite cardinal.
func (i Infinite) String() string {
	return "InfiniteCardinal"
}

// Add returns Infinite cardinal when adding with any other cardinal.
func (i Infinite) Add(other Cardinal) Cardinal {
	return Infinite{}
}

// Mul returns Infinite cardinal when multiplying with any other cardinal.
func (i Infinite) Mul(other Cardinal) Cardinal {
	return Infinite{}
}

// Big returns nil for Infinite cardinal.
func (i Infinite) Big() *big.Int {
	return nil
}

// Uint64 returns MaxUint64 for Infinite cardinal.
func (i Infinite) Uint64() uint64 {
	return math.MaxUint64
}

// IsZero always returns false for Infinite cardinal.
func (i Infinite) IsZero() bool {
	return false
}

// IsFinite always returns false for Infinite cardinal.
func (i Infinite) IsFinite() bool {
	return false
}

// IsUnknown always returns false for Infinite cardinal.
func (i Infinite) IsUnknown() bool {
	return false
}

// IsProbablyPrime always returns false for Infinite cardinal.
func (i Infinite) IsProbablyPrime() bool {
	return false
}

// BitLen returns 0 for Infinite cardinal.
func (i Infinite) BitLen() int {
	return 0
}
