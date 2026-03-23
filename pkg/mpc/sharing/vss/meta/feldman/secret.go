package feldman

import "github.com/bronlabs/bron-crypto/pkg/base/algebra"

// LiftedSecret is the group-element counterpart of a scalar secret. It holds
// the value [secret]G for a base point G.
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
