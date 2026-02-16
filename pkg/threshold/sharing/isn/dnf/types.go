package dnf

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
)

// Share represents a shareholder's portion in an ISN secret sharing scheme.
// Each share contains a sparse map from clause identifiers (represented as
// bitsets of party IDs) to group elements. The map only stores non-identity
// values, making the representation space-efficient for large access structures.
//
// For DNF schemes, keys are minimal qualified sets.
// Missing keys implicitly have the group identity value.
type Share[E algebra.GroupElement[E]] struct {
	id sharing.ID
	v  map[bitset.ImmutableBitSet[sharing.ID]]E
}

// ID returns the shareholder's unique identifier.
func (s *Share[E]) ID() sharing.ID {
	return s.id
}

// Value returns the share's sparse component map. Keys are clause identifiers
// (bitsets), and values are group elements. Missing keys implicitly represent
// the group identity element.
func (s *Share[E]) Value() map[bitset.ImmutableBitSet[sharing.ID]]E {
	return s.v
}

// Equal tests whether two shares are equal by comparing their IDs and
// all components of their value maps.
func (s *Share[E]) Equal(other *Share[E]) bool {
	if s == nil && other == nil {
		return s == other
	}
	if len(s.v) != len(other.v) {
		return false
	}
	for clause, si := range s.v {
		oi, exists := other.v[clause]
		if !exists || !si.Equal(oi) {
			return false
		}
	}
	return true
}

// Op performs component-wise group operation on two shares, enabling
// additive homomorphism. Combines entries from both maps, treating missing
// keys as the group identity element.
func (s *Share[E]) Op(other *Share[E]) *Share[E] {
	result := make(map[bitset.ImmutableBitSet[sharing.ID]]E)

	// Get a group instance from the first non-nil element
	var group algebra.FiniteGroup[E]
	for _, v := range s.v {
		group = algebra.StructureMustBeAs[algebra.FiniteGroup[E]](v.Structure())
		break
	}
	if group == nil {
		panic("cannot determine group from share components")
	}

	// Combine all clauses from both shares
	allClauses := make(map[bitset.ImmutableBitSet[sharing.ID]]bool)
	for clause := range s.v {
		allClauses[clause] = true
	}
	for clause := range other.v {
		allClauses[clause] = true
	}

	for clause := range allClauses {
		sVal, sExists := s.v[clause]
		oVal, oExists := other.v[clause]

		if sExists && oExists {
			result[clause] = sVal.Op(oVal)
		}
	}

	return &Share[E]{
		id: s.id,
		v:  result,
	}
}

// HashCode computes a hash combining the share ID and all value components.
func (s *Share[E]) HashCode() base.HashCode {
	c := base.HashCode(s.id)
	for _, si := range s.v {
		c = c.Combine(si.HashCode())
	}
	return c
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
