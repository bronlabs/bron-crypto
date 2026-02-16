package isn

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/errs-go/errs"
)

// SumToSecret takes a secret and a list of random shares, and computes the final shares such that their sum equals the secret. This is used in the dealing phase of ISN to generate shares that sum to the secret.
//
// Parameters:
//   - s: The secret to be shared
//   - prng: A cryptographically secure random number generator for sampling random shares
//   - l: The total number of shares to generate (including the final share)
//
// Returns a slice of shares that sum to the secret, or an error if any input is invalid or if sampling fails.
func SumToSecret[E algebra.GroupElement[E]](s *Secret[E], sampler func(io.Reader) (E, error), prng io.Reader, l int) ([]E, error) {
	if s == nil {
		return nil, ErrIsNil.WithMessage("secret is nil")
	}
	if sampler == nil {
		return nil, ErrIsNil.WithMessage("sampler is nil")
	}
	if prng == nil {
		return nil, ErrIsNil.WithMessage("prng is nil")
	}
	if l <= 0 {
		return nil, ErrFailed.WithMessage("number of shares must be positive")
	}
	group := algebra.StructureMustBeAs[algebra.Group[E]](s.v.Structure())

	rs := make([]E, l)
	partial := group.OpIdentity()
	for j := range l - 1 {
		rj, err := sampler(prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not sample random group element")
		}
		rs[j] = rj
		partial = partial.Op(rj)
	}
	rs[l-1] = s.v.Op(partial.OpInv())
	return rs, nil
}
