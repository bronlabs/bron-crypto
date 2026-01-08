package ecdsa

import (
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

// Signature represents an ECDSA signature consisting of two scalar values (r, s)
// and an optional recovery ID (v).
//
// The signature values are:
//   - r: the x-coordinate of the ephemeral public key R = k*G, reduced modulo n
//   - s: computed as s = k^(-1) * (z + r*d) mod n, where z is the message hash and d is the private key
//   - v: optional recovery ID (0-3) enabling public key recovery from the signature
//
// Reference: SEC 1 v2.0 Section 4.1: https://www.secg.org/sec1-v2.pdf
type Signature[S algebra.PrimeFieldElement[S]] struct {
	v *int
	r S
	s S
}

// NewSignature creates a Signature from r, s values and an optional recovery ID.
// Both r and s must be non-zero. If provided, v must be in the range [0, 3].
func NewSignature[S algebra.PrimeFieldElement[S]](r, s S, v *int) (*Signature[S], error) {
	if r.IsZero() || s.IsZero() {
		return nil, errs.NewFailed("r/s cannot be zero")
	}
	if v != nil && (*v < 0 || *v > 3) {
		return nil, errs.NewFailed("v must be 0/1/2/3")
	}

	sig := &Signature[S]{
		v,
		r,
		s,
	}
	return sig, nil
}

// Clone returns a deep copy of the signature.
func (sig *Signature[S]) Clone() *Signature[S] {
	var v *int
	if sig.v != nil {
		v = new(int)
		*v = *sig.v
	}
	clone := &Signature[S]{
		v: v,
		r: sig.r.Clone(),
		s: sig.s.Clone(),
	}
	return clone
}

// Equal returns true if both signatures have the same r and s values.
// Note: recovery ID (v) is not compared as it's metadata for key recovery.
func (sig *Signature[S]) Equal(rhs *Signature[S]) bool {
	if sig == nil || rhs == nil {
		return sig == rhs
	}
	return sig.r.Equal(rhs.r) && sig.s.Equal(rhs.s)
}

// HashCode returns a hash of the signature for use in hash-based data structures.
func (sig *Signature[S]) HashCode() base.HashCode {
	return sig.s.HashCode() ^ sig.r.HashCode()
}

// R returns the r component of the signature (x-coordinate of ephemeral public key mod n).
func (sig *Signature[S]) R() S {
	return sig.r
}

// S returns the s component of the signature.
func (sig *Signature[S]) S() S {
	return sig.s
}

// V returns the recovery ID, or nil if not set.
// The recovery ID enables public key recovery from the signature.
func (sig *Signature[S]) V() *int {
	return sig.v
}

// Normalise converts the signature to "low-S" canonical form.
//
// In ECDSA, both (r, s) and (r, n-s) are valid signatures for the same message.
// This malleability can cause issues in systems that use signature hashes as identifiers.
// Normalization ensures s is in the lower half of its range [1, n/2], providing
// a unique canonical representation.
//
// This is required by Bitcoin (BIP-62) and Ethereum to prevent transaction malleability.
// The recovery ID is also adjusted when s is negated.
//
// Reference: BIP-62 https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
func (sig *Signature[S]) Normalise() {
	if !sig.IsNormalized() {
		sig.s = sig.s.Neg()
		if sig.v != nil {
			v := *sig.v ^ 1
			sig.v = &v
		}
	}
}

// IsNormalized returns true if the signature is in low-S canonical form.
// A signature is normalized if s <= n/2, where n is the curve order.
func (sig *Signature[S]) IsNormalized() bool {
	return sig.s.Cardinal().Big().Cmp(sig.s.Neg().Cardinal().Big()) <= 0
}

// ToElliptic returns the r and s values as big.Int for use with Go's crypto/ecdsa package.
func (sig *Signature[S]) ToElliptic() (r *big.Int, s *big.Int) {
	nativeR := sig.r.Cardinal().Big()
	nativeS := sig.s.Cardinal().Big()
	return nativeR, nativeS
}
