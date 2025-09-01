package ecdsa

import (
	"bytes"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

// DigestToScalar sets scalar to the left-most bits of hash, according to
// FIPS 186-5, Section 6.4.1, point 2 and Section 6.4.2, point 3.
func DigestToScalar[S algebra.PrimeFieldElement[S]](field algebra.PrimeField[S], digest []byte) (S, error) {
	// ECDSA asks us to take the left-most log2(N) bits of hash, and use them as
	// an integer modulo N. This is the absolute worst of all worlds: we still
	// have to reduce, because the result might still overflow N, but to take
	// the left-most bits for P-521 we have to do a right shift.
	var nilS S
	n := field.ElementSize()
	if size := n; len(digest) >= size {
		digest = digest[:size]
		if excess := len(digest)*8 - field.BitLen(); excess > 0 {
			var err error
			digest, err = rightShift(digest, excess)
			if err != nil {
				return nilS, errs.WrapFailed(err, "internal error")
			}
		}
	}
	s, err := field.FromWideBytes(digest)
	if err != nil {
		return nilS, errs.WrapFailed(err, "truncated digest is too long")
	}
	return s, nil
}

// rightShift implements the right shift necessary for bits2int, which takes the
// leftmost bits of either the hash or HMAC_DRBG output.
//
// Note how taking the rightmost bits would have been as easy as masking the
// first byte, but we can't have nice things.
func rightShift(b []byte, shift int) ([]byte, error) {
	if shift <= 0 || shift >= 8 {
		return nil, errs.NewFailed("shift can only be by 1 to 7 bits")
	}
	b = bytes.Clone(b)
	for i := len(b) - 1; i >= 0; i-- {
		b[i] >>= shift
		if i > 0 {
			b[i] |= b[i-1] << (8 - shift)
		}
	}
	return b, nil
}
