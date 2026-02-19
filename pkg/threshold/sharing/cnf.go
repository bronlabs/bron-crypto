package sharing

import (
	"iter"
	"slices"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/errs-go/errs"
)

var _ MonotoneAccessStructure = (*CNFAccessStructure)(nil)

type CNFAccessStructure struct {
	shareholders           ds.Set[ID]
	maximalUnqualifiedSets []ds.Set[ID]
}

func NewCNFAccessStructure(unqualifiedSets ...ds.Set[ID]) (*CNFAccessStructure, error) {
	maximalUnqualifiedSets, err := normaliseCNF(unqualifiedSets...)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	shareholders := hashset.NewComparable[ID]()
	for _, u := range maximalUnqualifiedSets {
		shareholders.AddAll(u.List()...)
	}
	if shareholders.Size() < 2 {
		return nil, ErrMembership.WithMessage("shareholders must be a set of at least 2 distinct IDs, excluding 0")
	}

	c := &CNFAccessStructure{
		shareholders:           shareholders.Freeze(),
		maximalUnqualifiedSets: maximalUnqualifiedSets,
	}
	return c, nil
}

func (c *CNFAccessStructure) IsQualified(ids ...ID) bool {
	if c == nil || c.shareholders == nil {
		return false
	}

	idSet := hashset.NewComparable(ids...).Freeze()
	if !idSet.IsSubSet(c.shareholders) {
		return false
	}
	for _, u := range c.maximalUnqualifiedSets {
		if idSet.IsSubSet(u) {
			return false
		}
	}
	return true
}

func (c *CNFAccessStructure) Shareholders() ds.Set[ID] {
	return c.shareholders
}

func (c *CNFAccessStructure) MaximalUnqualifiedSetsIter() iter.Seq[ds.Set[ID]] {
	if c == nil || len(c.maximalUnqualifiedSets) == 0 {
		return slices.Values([]ds.Set[ID]{})
	}
	return slices.Values(c.maximalUnqualifiedSets)
}

func normaliseCNF(unqualifiedSets ...ds.Set[ID]) ([]ds.Set[ID], error) {
	if len(unqualifiedSets) == 0 {
		return nil, ErrValue.WithMessage("must have at least one unqualified set")
	}

	uniqueSets := make([]ds.Set[ID], 0, len(unqualifiedSets))
	for _, s := range unqualifiedSets {
		if s == nil {
			return nil, ErrIsNil.WithMessage("unqualified set cannot be nil")
		}
		if s.IsEmpty() {
			return nil, ErrValue.WithMessage("unqualified set cannot be empty")
		}
		if s.Contains(0) {
			return nil, ErrMembership.WithMessage("unqualified set cannot contain shareholder ID 0")
		}
		normalized := hashset.NewComparable[ID](s.List()...).Freeze()

		alreadySeen := false
		for _, seen := range uniqueSets {
			if normalized.Equal(seen) {
				alreadySeen = true
				break
			}
		}
		if !alreadySeen {
			uniqueSets = append(uniqueSets, normalized)
		}
	}

	maximalSets := make([]ds.Set[ID], 0, len(uniqueSets))
	for i, si := range uniqueSets {
		isMaximal := true
		for j, sj := range uniqueSets {
			if i == j {
				continue
			}
			if si.IsSubSet(sj) {
				isMaximal = false
				break
			}
		}
		if isMaximal {
			maximalSets = append(maximalSets, si)
		}
	}

	return maximalSets, nil
}
