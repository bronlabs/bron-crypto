package internal

import (
	"iter"
	"maps"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

const maxShareholders = 64

var (
	ErrInvalidArgument = errs.New("invalid argument")
	ErrOverflow        = errs.New("overflow")
)

// BruteForceMaximalUnqualifiedSets returns an iterator over all maximal
// unqualified subsets of shareholders by exhaustive search.
//
// The search enumerates shareholder subsets in descending cardinality and keeps
// only those unqualified subsets that are not contained in an already-found
// larger unqualified subset.
//
// This helper uses a bitset representation keyed directly by shareholder IDs,
// so it requires:
//   - shareholders != nil
//   - isQualified != nil
//   - shareholders is non-empty
//   - every shareholder ID is in the range [1, 64]
//
// It returns ErrInvalidArgument for nil/empty inputs and ErrOverflow when any
// shareholder ID exceeds 64.
func BruteForceMaximalUnqualifiedSets(shareholders ds.Set[sharing.ID], isQualified func(ids ...sharing.ID) bool) (iter.Seq[ds.Set[sharing.ID]], error) {
	if shareholders == nil || isQualified == nil || shareholders.Size() < 1 {
		return nil, ErrInvalidArgument.WithMessage("invalid arguments")
	}
	sortedShareholders := slices.Sorted(shareholders.Iter())
	if sortedShareholders[len(sortedShareholders)-1] > maxShareholders {
		return nil, ErrOverflow.WithMessage("too many shareholders")
	}

	muss := make(map[bitset.BitSet[sharing.ID]]struct{})
	for t := len(sortedShareholders); t >= 1; t-- {
	next:
		for s := range sliceutils.Combinations(sortedShareholders, uint(t)) {
			if isQualified(s...) {
				continue
			}

			// s is unqualified, check if it's not a subset of existing unqualified sets
			s2 := *bitset.NewBitSet(s...)
			for mus := range maps.Keys(muss) {
				if s2.IsSubSet(&mus) {
					continue next
				}
			}

			muss[s2] = struct{}{}
		}
	}

	return func(yield func(ds.Set[sharing.ID]) bool) {
		for mus := range muss {
			if !yield(hashset.NewComparable(mus.List()...).Freeze()) {
				return
			}
		}
	}, nil
}
