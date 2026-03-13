package kw

import "github.com/bronlabs/bron-crypto/pkg/base/algebra"

// Secret wraps a finite field element that is being shared.
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

type LiftedSecret[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	v E
}

// NewLiftedSecret creates a new lifted secret from a group element.
func NewLiftedSecret[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](value E) *LiftedSecret[E, FE] {
	return &LiftedSecret[E, FE]{v: value}
}

// Value returns the underlying group element.
func (s *LiftedSecret[E, FE]) Value() E {
	return s.v
}

// Equal returns true if two lifted secrets have the same value.
func (s *LiftedSecret[E, FE]) Equal(other *LiftedSecret[E, FE]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.v.Equal(other.v)
}

// Clone returns a deep copy of this lifted secret.
func (s *LiftedSecret[E, FE]) Clone() *LiftedSecret[E, FE] {
	return &LiftedSecret[E, FE]{
		v: s.v.Clone(),
	}
}
