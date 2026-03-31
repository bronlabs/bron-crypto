package tassa

import "github.com/bronlabs/bron-crypto/pkg/base/algebra"

// Secret is a Tassa secret represented as a prime-field element.
type Secret[F algebra.PrimeFieldElement[F]] struct {
	value F
}

// NewSecret constructs a secret wrapper from a field element.
func NewSecret[F algebra.PrimeFieldElement[F]](value F) *Secret[F] {
	return &Secret[F]{
		value: value,
	}
}

// Equal reports whether two secrets are equal.
func (s *Secret[F]) Equal(r *Secret[F]) bool {
	if s == nil || r == nil {
		return s == r
	}

	return s.value.Equal(r.value)
}

// Value returns the underlying field element.
func (s *Secret[F]) Value() F {
	return s.value
}
