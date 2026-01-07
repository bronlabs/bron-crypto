package shamir

import "github.com/bronlabs/bron-crypto/pkg/base/algebra"

// Secret wraps a prime field element that is being shared.
type Secret[FE algebra.PrimeFieldElement[FE]] struct {
	v FE
}

// NewSecret creates a new secret from a field element.
func NewSecret[FE algebra.PrimeFieldElement[FE]](value FE) *Secret[FE] {
	return &Secret[FE]{v: value}
}

// Value returns the underlying field element.
func (s *Secret[FE]) Value() FE {
	return s.v
}

// Equal returns true if two secrets have the same value.
func (s *Secret[FE]) Equal(other *Secret[FE]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.v.Equal(other.v)
}

// Clone returns a deep copy of this secret.
func (s *Secret[FE]) Clone() *Secret[FE] {
	return &Secret[FE]{
		v: s.v.Clone(),
	}
}
