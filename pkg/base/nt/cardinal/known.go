package cardinal

import (
	"math/big"
	"math/bits"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	acrtp "github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

// New creates a new Known cardinal from a uint64 value.
func New(n uint64) Cardinal {
	var nat numct.Nat
	nat.SetUint64(n)
	nat.Resize(bits.Len64(n))
	return Known(nat.BytesBE())
}

// NewFromBig creates a new Cardinal from a big.Int value.
func NewFromBig(n *big.Int) Cardinal {
	if n == nil {
		return Unknown()
	}
	if n.Sign() < 0 {
		return Unknown()
	}
	return Known(numct.NewNatFromBig(n, n.BitLen()).BytesBE())
}

// NewFromNumeric creates a new Cardinal from a Numeric value.
func NewFromNumeric(num acrtp.Numeric) Cardinal {
	return Known(num.BytesBE())
}

// Zero returns the zero cardinal.
func Zero() Cardinal {
	return Known([]byte{})
}

// Known represents a cardinal number with a known value.
type Known []byte

// Nat returns the numeric representation of the known cardinal.
func (k Known) Nat() *numct.Nat {
	return numct.NewNatFromBytes(k)
}

// IsLessThanOrEqual checks if the known cardinal is less than or equal to another cardinal.
func (k Known) IsLessThanOrEqual(other Cardinal) bool {
	otherKnown, ok := other.(Known)
	if !ok {
		return false
	}
	lt, eq, _ := k.Nat().Compare(otherKnown.Nat())
	return lt|eq == ct.True
}

// Clone creates a copy of the known cardinal.
func (k Known) Clone() Cardinal {
	return slices.Clone(k)
}

// HashCode computes the hash code of the known cardinal.
func (k Known) HashCode() base.HashCode {
	return base.DeriveHashCode(k)
}

// Equal checks if the known cardinal is equal to another cardinal.
func (k Known) Equal(other Cardinal) bool {
	otherKnown, ok := other.(Known)
	if !ok {
		return false
	}
	return k.Nat().Equal(otherKnown.Nat()) == ct.True
}

// Bytes returns the byte representation of the known cardinal.
func (k Known) Bytes() []byte {
	return slices.Clone(k)
}

// BytesBE returns the big-endian byte representation of the known cardinal.
func (k Known) BytesBE() []byte {
	return slices.Clone(k)
}

// String returns the string representation of the known cardinal.
func (k Known) String() string {
	return k.Nat().String()
}

// Add adds two known cardinals.
func (k Known) Add(other Cardinal) Cardinal {
	otherKnown, _ := other.(Known)
	var sum numct.Nat
	sum.Add(k.Nat(), otherKnown.Nat())
	return Known(sum.BytesBE())
}

// Mul multiplies two known cardinals.
func (k Known) Mul(other Cardinal) Cardinal {
	otherKnown, _ := other.(Known)
	var prod numct.Nat
	prod.Mul(k.Nat(), otherKnown.Nat())
	return Known(prod.BytesBE())
}

// Sub subtracts another known cardinal from the known cardinal.
func (k Known) Sub(other Cardinal) Cardinal {
	otherKnown, _ := other.(Known)
	var diff numct.Nat
	diff.SubCap(k.Nat(), otherKnown.Nat(), -1)
	return Known(diff.BytesBE())
}

// Big returns the big.Int representation of the known cardinal.
func (k Known) Big() *big.Int {
	return k.Nat().Big()
}

// Uint64 returns the uint64 representation of the known cardinal.
func (k Known) Uint64() uint64 {
	return k.Nat().Uint64()
}

// IsZero checks if the known cardinal is zero.
func (k Known) IsZero() bool {
	return k.Nat().IsZero() == ct.True
}

// IsFinite checks if the known cardinal is finite, which is always true for Known.
func (k Known) IsFinite() bool {
	return true
}

// IsUnknown checks if the known cardinal is unknown, which is always false for Known.
func (k Known) IsUnknown() bool {
	return false
}

// IsProbablyPrime checks if the known cardinal is probably prime.
func (k Known) IsProbablyPrime() bool {
	return k.Nat().IsProbablyPrime() == ct.True
}

// BitLen returns the bit length of the known cardinal.
func (k Known) BitLen() int {
	return k.Nat().AnnouncedLen()
}
