package ecdsa

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

type Signature[S algebra.PrimeFieldElement[S]] struct {
	v *int
	r S
	s S
}

// TODO: do the magic
func NewSignature[S algebra.PrimeFieldElement[S]](r, s S, v *int) *Signature[S] {
	return &Signature[S]{
		v,
		r,
		s,
	}
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
