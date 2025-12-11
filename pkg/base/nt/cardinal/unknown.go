package cardinal

import (
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base"
)

// Unknown represents a cardinal of unknown size.
type Unknown struct{}

// IsLessThanOrEqual always returns false for Unknown cardinal.
func (u Unknown) IsLessThanOrEqual(other Cardinal) bool {
	return false
}

// Clone returns a new instance of Unknown cardinal.
func (u Unknown) Clone() Cardinal {
	return Unknown{}
}

// HashCode returns a hash code for Unknown cardinal.
func (u Unknown) HashCode() base.HashCode {
	return base.DeriveHashCode([]byte("UnknownCardinal"))
}

// Equal always returns false when comparing Unknown cardinal with any other cardinal.
func (u Unknown) Equal(other Cardinal) bool {
	return false
}

// Bytes returns an empty byte slice for Unknown cardinal.
func (u Unknown) Bytes() []byte {
	return nil
}

// BytesBE returns an empty byte slice for Unknown cardinal.
func (u Unknown) BytesBE() []byte {
	return nil
}

// String returns a string representation of Unknown cardinal.
func (u Unknown) String() string {
	return "UnknownCardinal"
}

// Add returns Unknown cardinal when adding to any other cardinal.
func (u Unknown) Add(other Cardinal) Cardinal {
	return Unknown{}
}

// Mul returns Unknown cardinal when multiplying with any other cardinal.
func (u Unknown) Mul(other Cardinal) Cardinal {
	return Unknown{}
}

// Big returns nil for Unknown cardinal.
func (u Unknown) Big() *big.Int {
	return nil
}

// Uint64 returns 0 for Unknown cardinal.
func (u Unknown) Uint64() uint64 {
	return 0
}

// IsZero always returns false for Unknown cardinal.
func (u Unknown) IsZero() bool {
	return false
}

// IsFinite always returns true for Unknown cardinal.
func (u Unknown) IsFinite() bool {
	return true
}

// IsUnknown always returns true for Unknown cardinal.
func (u Unknown) IsUnknown() bool {
	return true
}

// IsProbablyPrime always returns false for Unknown cardinal.
func (u Unknown) IsProbablyPrime() bool {
	return false
}

// BitLen returns 0 for Unknown cardinal.
func (u Unknown) BitLen() int {
	return 0
}
