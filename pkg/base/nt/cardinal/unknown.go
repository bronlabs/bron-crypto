package cardinal

import (
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base"
)

var u Cardinal = unknown{}

func Unknown() Cardinal {
	return u
}

// unknown represents a cardinal of unknown size.
type unknown struct{}

// IsLessThanOrEqual always returns false for Unknown cardinal.
func (u unknown) IsLessThanOrEqual(other Cardinal) bool {
	return false
}

// Clone returns a new instance of Unknown cardinal.
func (u unknown) Clone() Cardinal {
	return Unknown()
}

// HashCode returns a hash code for Unknown cardinal.
func (u unknown) HashCode() base.HashCode {
	return base.DeriveHashCode([]byte("UnknownCardinal"))
}

// Equal always returns false when comparing Unknown cardinal with any other cardinal.
func (u unknown) Equal(other Cardinal) bool {
	return false
}

// Bytes panics as Bytes is not defined for Unknown cardinal.
func (u unknown) Bytes() []byte {
	panic("Bytes() not implemented for Unknown cardinal")
}

// BytesBE panics as BytesBE is not defined for Unknown cardinal.
func (u unknown) BytesBE() []byte {
	panic("BytesBE() not implemented for Unknown cardinal")
}

// String returns a string representation of Unknown cardinal.
func (u unknown) String() string {
	return "UnknownCardinal"
}

// Add returns Unknown cardinal when adding to any other cardinal.
func (u unknown) Add(other Cardinal) Cardinal {
	return Unknown()
}

// Mul returns Unknown cardinal when multiplying with any other cardinal.
func (u unknown) Mul(other Cardinal) Cardinal {
	return Unknown()
}

// Big panics as Big is not defined for Unknown cardinal.
func (u unknown) Big() *big.Int {
	panic("Big() not implemented for Unknown cardinal")
}

// Uint64 panics as Uint64 is not defined for Unknown cardinal.
func (u unknown) Uint64() uint64 {
	panic("Uint64() not implemented for Unknown cardinal")
}

// IsZero always returns false for Unknown cardinal.
func (u unknown) IsZero() bool {
	return false
}

// IsFinite always returns true for Unknown cardinal.
func (u unknown) IsFinite() bool {
	return true
}

// IsUnknown always returns true for Unknown cardinal.
func (u unknown) IsUnknown() bool {
	return true
}

// IsProbablyPrime panics as IsProbablyPrime is not defined for Unknown cardinal.
func (u unknown) IsProbablyPrime() bool {
	panic("IsProbablyPrime() not implemented for Unknown cardinal")
}

// BitLen panics as BitLen is not defined for Unknown cardinal.
func (u unknown) BitLen() int {
	panic("BitLen() not implemented for Unknown cardinal")
}
