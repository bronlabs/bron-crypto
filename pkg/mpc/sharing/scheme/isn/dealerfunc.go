package isn

import (
	"iter"
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
)

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

// Op performs a component-wise group operation on two dealer functions.
func (df DealerFunc[E]) Op(other DealerFunc[E]) DealerFunc[E] {
	result := make(DealerFunc[E])
	for clause, value := range df {
		if otherValue, exists := other[clause]; exists {
			result[clause] = value.Op(otherValue)
		}
	}
	return result
}

// Repr returns an iterator that yields the dealer function's clause values
// in deterministic order (sorted by clause key).
func (df DealerFunc[E]) Repr() iter.Seq[E] {
	return func(yield func(E) bool) {
		keys := make([]bitset.ImmutableBitSet[sharing.ID], 0, len(df))
		for k := range df {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			if !yield(df[k]) {
				return
			}
		}
	}
}

// Accepts checks whether this dealer function is compatible with the given
// access structure by verifying it has entries for all required clauses.
func (df DealerFunc[E]) Accepts(ac *accessstructures.CNF) bool {
	if ac == nil {
		return false
	}
	cs := hashset.NewComparable(clauses(ac)...)
	dfs := hashset.NewComparable(slices.Collect(maps.Keys(df))...)
	return cs.Equal(dfs)
}

// LiftedDealerFunc wraps a map from clause bitsets to group elements,
// providing the interface required by meta Feldman and meta Pedersen schemes
// for ISN-based underlying LSSS.
type LiftedDealerFunc[
	E algebra.ModuleElement[E, S],
	S algebra.RingElement[S],
] map[bitset.ImmutableBitSet[sharing.ID]]E

// ShareOf derives the lifted share for shareholder id by filtering clauses
// that do not contain the shareholder (same logic as isn.DealerFunc.ShareOf).
func (ldf LiftedDealerFunc[E, S]) ShareOf(id sharing.ID) *LiftedShare[E] {
	shareValues := make(map[bitset.ImmutableBitSet[sharing.ID]]E)
	for clause, value := range ldf {
		if !clause.Contains(id) {
			shareValues[clause] = value
		}
	}
	return &LiftedShare[E]{Share: Share[E]{id: id, v: shareValues}}
}

// Accepts returns true if the lifted dealer function has entries.
func (ldf LiftedDealerFunc[E, S]) Accepts(ac *accessstructures.CNF) bool {
	if ac == nil {
		return false
	}
	cs := hashset.NewComparable(clauses(ac)...)
	dfs := hashset.NewComparable(slices.Collect(maps.Keys(ldf))...)
	return cs.Equal(dfs)
}

// Op returns a new LiftedISNDealerFunc that is the clause-wise group
// operation of two lifted dealer functions.
func (ldf LiftedDealerFunc[E, S]) Op(other LiftedDealerFunc[E, S]) LiftedDealerFunc[E, S] {
	result := make(map[bitset.ImmutableBitSet[sharing.ID]]E)
	for clause, value := range ldf {
		if otherValue, exists := other[clause]; exists {
			result[clause] = value.Op(otherValue)
		}
	}
	return LiftedDealerFunc[E, S](result)
}

// Repr yields clause values in deterministic order (sorted by clause key).
func (ldf LiftedDealerFunc[E, S]) Repr() iter.Seq[E] {
	return func(yield func(E) bool) {
		keys := make([]bitset.ImmutableBitSet[sharing.ID], 0, len(ldf))
		for k := range ldf {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			if !yield(ldf[k]) {
				return
			}
		}
	}
}
