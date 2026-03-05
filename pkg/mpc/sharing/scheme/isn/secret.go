package isn

import "github.com/bronlabs/bron-crypto/pkg/base/algebra"

// Secret represents a shared secret value in an ISN scheme. The secret
// is an element of a finite group and can be split into shares using
// either the DNF or CNF dealing algorithm.
type Secret[E algebra.GroupElement[E]] struct {
	v E
}

// NewSecret creates a new secret from a group element.
func NewSecret[E algebra.GroupElement[E]](v E) *Secret[E] {
	return &Secret[E]{v: v}
}

// Value returns the underlying group element of the secret.
func (s *Secret[E]) Value() E {
	return s.v
}

// Equal tests whether two secrets have equal values.
func (s *Secret[E]) Equal(other *Secret[E]) bool {
	if s == nil && other == nil {
		return s == other
	}
	return s.v.Equal(other.v)
}

// Clone creates a deep copy of the secret.
func (s *Secret[E]) Clone() *Secret[E] {
	return &Secret[E]{
		v: s.v.Clone(),
	}
}

type LiftedSecret[E algebra.ModuleElement[E, FE], FE algebra.RingElement[FE]] struct {
	v E
}

// NewLiftedSecret creates a new lifted secret from a group element.
func NewLiftedSecret[E algebra.ModuleElement[E, FE], FE algebra.RingElement[FE]](v E) *LiftedSecret[E, FE] {
	return &LiftedSecret[E, FE]{v: v}
}

// Value returns the underlying group element of the lifted secret.
func (s *LiftedSecret[E, FE]) Value() E {
	return s.v
}

// Equal tests whether two lifted secrets have equal values.
func (s *LiftedSecret[E, FE]) Equal(other *LiftedSecret[E, FE]) bool {
	if s == nil && other == nil {
		return s == other
	}
	return s.v.Equal(other.v)
}

// Clone creates a deep copy of the lifted secret.
func (s *LiftedSecret[E, FE]) Clone() *LiftedSecret[E, FE] {
	return &LiftedSecret[E, FE]{
		v: s.v.Clone(),
	}
}
