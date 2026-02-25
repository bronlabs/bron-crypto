package isn

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// Name is the human-readable name for ISN secret sharing.
const Name sharing.Name = "ISN secret sharing scheme"

// DealerFunc represents the dealer function that maps shareholder IDs to their
// shares. This is returned by LSSS methods that reveal the dealer function,
// enabling protocols that require knowledge of the complete share distribution.
type DealerFunc[E algebra.GroupElement[E]] map[bitset.ImmutableBitSet[sharing.ID]]E

// ShareOf derives the share for shareholder id from the dealer function.
func (df DealerFunc[E]) ShareOf(id sharing.ID) *Share[E] {
	shareValue := make(map[bitset.ImmutableBitSet[sharing.ID]]E)
	for clause, value := range df {
		if !clause.Contains(id) {
			shareValue[clause] = value
		}
	}

	return &Share[E]{
		id: id,
		v:  shareValue,
	}
}

// DealerOutput contains the shares produced by a dealing operation.
// It provides access to the mapping from shareholder IDs to their shares.
type DealerOutput[E algebra.GroupElement[E]] struct {
	shares ds.Map[sharing.ID, *Share[E]]
}

// Shares returns the map of shareholder IDs to their corresponding shares.
func (d *DealerOutput[E]) Shares() ds.Map[sharing.ID, *Share[E]] {
	return d.shares
}

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
