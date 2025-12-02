package ecdsa

import (
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type Signature[S algebra.PrimeFieldElement[S]] struct {
	v *int
	r S
	s S
}

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

func (sig *Signature[S]) Equal(rhs *Signature[S]) bool {
	if sig == nil || rhs == nil {
		return sig == rhs
	}
	return sig.r.Equal(rhs.r) && sig.s.Equal(rhs.s)
}

func (sig *Signature[S]) HashCode() base.HashCode {
	return sig.s.HashCode() ^ sig.r.HashCode()
}

func (sig *Signature[S]) R() S {
	return sig.r
}

func (sig *Signature[S]) S() S {
	return sig.s
}

func (sig *Signature[S]) V() *int {
	return sig.v
}

// Normalise normalises the signature to a "low S" form. In ECDSA, signatures are
// of the form (r, s) where r and s are numbers lying in some finite
// field. Both (r, s) and (r, -s) are valid signatures of the same message,
// so ECDSA does not have a strong existential unforgeability
// We normalise to the low S form which ensures that the s value
// lies in the lower half of its range.
// See <https://en.bitcoin.it/wiki/BIP_0062#Low_S_values_in_signatures>
func (sig *Signature[S]) Normalise() {
	if !sig.IsNormalized() {
		sig.s = sig.s.Neg()
		if sig.v != nil {
			v := *sig.v ^ 1
			sig.v = &v
		}
	}
}

func (sig *Signature[S]) IsNormalized() bool {
	return sig.s.Cardinal().Big().Cmp(sig.s.Neg().Cardinal().Big()) <= 0
}

func (sig *Signature[S]) ToElliptic() (r *big.Int, s *big.Int) {
	nativeR := sig.r.Cardinal().Big()
	nativeS := sig.s.Cardinal().Big()
	return nativeR, nativeS
}
