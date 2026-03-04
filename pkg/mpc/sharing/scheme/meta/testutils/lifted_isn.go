package testutils

import (
	"iter"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/isn"
)

// LiftedISNDealerFunc wraps a map from clause bitsets to group elements,
// providing the interface required by meta Feldman and meta Pedersen schemes
// for ISN-based underlying LSSS.
type LiftedISNDealerFunc[
	E algebra.GroupElement[E],
	FE algebra.PrimeFieldElement[FE],
	AC accessstructures.Monotone,
] struct {
	values map[bitset.ImmutableBitSet[sharing.ID]]E
}

// ShareOf derives the lifted share for shareholder id by filtering clauses
// that do not contain the shareholder (same logic as isn.DealerFunc.ShareOf).
func (ldf *LiftedISNDealerFunc[E, FE, AC]) ShareOf(id sharing.ID) *LiftedISNShare[E] {
	shareValues := make(map[bitset.ImmutableBitSet[sharing.ID]]E)
	for clause, value := range ldf.values {
		if !clause.Contains(id) {
			shareValues[clause] = value
		}
	}
	return &LiftedISNShare[E]{id: id, values: shareValues}
}

// Accepts returns true if the lifted dealer function has entries.
func (ldf *LiftedISNDealerFunc[E, FE, AC]) Accepts(_ AC) bool {
	return len(ldf.values) > 0
}

// Op returns a new LiftedISNDealerFunc that is the clause-wise group
// operation of two lifted dealer functions.
func (ldf *LiftedISNDealerFunc[E, FE, AC]) Op(other *LiftedISNDealerFunc[E, FE, AC]) *LiftedISNDealerFunc[E, FE, AC] {
	result := make(map[bitset.ImmutableBitSet[sharing.ID]]E)
	for clause, value := range ldf.values {
		if otherValue, exists := other.values[clause]; exists {
			result[clause] = value.Op(otherValue)
		}
	}
	return &LiftedISNDealerFunc[E, FE, AC]{values: result}
}

// Repr yields clause values in deterministic order (sorted by clause key).
func (ldf *LiftedISNDealerFunc[E, FE, AC]) Repr() iter.Seq[E] {
	return func(yield func(E) bool) {
		keys := make([]bitset.ImmutableBitSet[sharing.ID], 0, len(ldf.values))
		for k := range ldf.values {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			if !yield(ldf.values[k]) {
				return
			}
		}
	}
}

// LiftedISNShare wraps share clause values as group elements for a
// specific shareholder.
type LiftedISNShare[E algebra.GroupElement[E]] struct {
	id     sharing.ID
	values map[bitset.ImmutableBitSet[sharing.ID]]E
}

// ID returns the shareholder identifier.
func (ls *LiftedISNShare[E]) ID() sharing.ID {
	return ls.id
}

// Repr yields clause values in deterministic order (sorted by clause key).
func (ls *LiftedISNShare[E]) Repr() iter.Seq[E] {
	return func(yield func(E) bool) {
		keys := make([]bitset.ImmutableBitSet[sharing.ID], 0, len(ls.values))
		for k := range ls.values {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			if !yield(ls.values[k]) {
				return
			}
		}
	}
}

// Equal returns true if two LiftedISNShares have the same ID and values.
func (ls *LiftedISNShare[E]) Equal(other *LiftedISNShare[E]) bool {
	if ls == nil || other == nil {
		return ls == other
	}
	if ls.id != other.id || len(ls.values) != len(other.values) {
		return false
	}
	for clause, val := range ls.values {
		otherVal, exists := other.values[clause]
		if !exists || !val.Equal(otherVal) {
			return false
		}
	}
	return true
}

// HashCode returns a hash code for this lifted ISN share.
func (ls *LiftedISNShare[E]) HashCode() base.HashCode {
	return base.HashCode(ls.id)
}

// LiftISNDealerFunc lifts an ISN dealer function (map of clause→scalar)
// into a lifted dealer function (map of clause→group element) by exponentiating
// each clause value via basePoint.ScalarOp(value).
func LiftISNDealerFunc[
	E algebra.ModuleElement[E, FE],
	FE algebra.PrimeFieldElement[FE],
	AC accessstructures.Monotone,
](df isn.DealerFunc[FE], basePoint E) (*LiftedISNDealerFunc[E, FE, AC], error) {
	lifted := make(map[bitset.ImmutableBitSet[sharing.ID]]E, len(df))
	for clause, value := range df {
		lifted[clause] = basePoint.ScalarOp(value)
	}
	return &LiftedISNDealerFunc[E, FE, AC]{values: lifted}, nil
}
