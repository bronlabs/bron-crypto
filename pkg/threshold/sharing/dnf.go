package sharing

import (
	"iter"
	"slices"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/errs-go/errs"
)

var _ MonotoneAccessStructure = (*DNFAccessStructure)(nil)

type DNFAccessStructure struct {
	shareholders         ds.Set[ID]
	minimalQualifiedSets []ds.Set[ID]
}

func NewDNFAccessStructure(qualifiedSets ...ds.Set[ID]) (*DNFAccessStructure, error) {
	minimalQualifiedSets, err := normaliseDNF(qualifiedSets...)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	shareholders := hashset.NewComparable[ID]()
	for _, q := range minimalQualifiedSets {
		shareholders.AddAll(q.List()...)
	}
	if shareholders.Size() < 2 {
		return nil, ErrMembership.WithMessage("shareholders must be a set of at least 2 distinct IDs, excluding 0")
	}

	d := &DNFAccessStructure{
		shareholders:         shareholders.Freeze(),
		minimalQualifiedSets: minimalQualifiedSets,
	}
	return d, nil
}

func (d *DNFAccessStructure) IsQualified(ids ...ID) bool {
	if d == nil || d.shareholders == nil {
		return false
	}

	idSet := hashset.NewComparable(ids...).Freeze()
	if !idSet.IsSubSet(d.shareholders) {
		return false
	}
	for _, q := range d.minimalQualifiedSets {
		if q.IsSubSet(idSet) {
			return true
		}
	}
	return false
}

func (d *DNFAccessStructure) Shareholders() ds.Set[ID] {
	return d.shareholders
}

func (d *DNFAccessStructure) MaximalUnqualifiedSetsIter() iter.Seq[ds.Set[ID]] {
	if d == nil || d.shareholders == nil {
		return slices.Values([]ds.Set[ID]{})
	}

	// If there are no minimal qualified sets, every subset is unqualified and
	// the unique maximal one is the whole shareholder universe.
	if len(d.minimalQualifiedSets) == 0 {
		return slices.Values([]ds.Set[ID]{d.shareholders.Clone()})
	}

	return func(yield func(ds.Set[ID]) bool) {
		chosen := hashset.NewComparable[ID]()
		excluded := hashset.NewComparable[ID]()

		var rec func() bool
		rec = func() bool {
			if !allChosenHaveCritical(d.minimalQualifiedSets, chosen) {
				return true
			}

			uncovered, ok := firstUncoveredSet(d.minimalQualifiedSets, chosen)
			if !ok {
				maxUnqualified := complementSet(d.shareholders, chosen)
				return yield(maxUnqualified)
			}

			candidates := make([]ID, 0, uncovered.Size())
			for id := range uncovered.Iter() {
				if !excluded.Contains(id) {
					candidates = append(candidates, id)
				}
			}
			if len(candidates) == 0 {
				return true
			}
			slices.Sort(candidates)

			for i, id := range candidates {
				chosen.Add(id)

				addedExcluded := make([]ID, 0, i)
				for _, prior := range candidates[:i] {
					if !excluded.Contains(prior) {
						excluded.Add(prior)
						addedExcluded = append(addedExcluded, prior)
					}
				}

				if canStillHitAllSets(d.minimalQualifiedSets, chosen, excluded) {
					if !rec() {
						return false
					}
				}

				excluded.RemoveAll(addedExcluded...)
				chosen.Remove(id)
			}

			return true
		}

		_ = rec()
	}
}

//nolint:dupl // Keep DNF normalisation logic explicit and parallel to CNF for readability.
func normaliseDNF(qualifiedSets ...ds.Set[ID]) ([]ds.Set[ID], error) {
	if len(qualifiedSets) == 0 {
		return nil, ErrValue.WithMessage("must have at least one qualified set")
	}

	uniqueSets := make([]ds.Set[ID], 0, len(qualifiedSets))
	for _, s := range qualifiedSets {
		if s == nil {
			return nil, ErrIsNil.WithMessage("qualified set cannot be nil")
		}
		if s.IsEmpty() {
			return nil, ErrValue.WithMessage("qualified set cannot be empty")
		}
		if s.Contains(0) {
			return nil, ErrMembership.WithMessage("qualified set cannot contain shareholder ID 0")
		}
		normalised := hashset.NewComparable[ID](s.List()...).Freeze()

		alreadySeen := false
		for _, seen := range uniqueSets {
			if normalised.Equal(seen) {
				alreadySeen = true
				break
			}
		}
		if !alreadySeen {
			uniqueSets = append(uniqueSets, normalised)
		}
	}

	minimalSets := make([]ds.Set[ID], 0, len(uniqueSets))
	for i, si := range uniqueSets {
		isMinimal := true
		for j, sj := range uniqueSets {
			if i == j {
				continue
			}
			if sj.IsSubSet(si) {
				isMinimal = false
				break
			}
		}
		if isMinimal {
			minimalSets = append(minimalSets, si)
		}
	}

	return minimalSets, nil
}

func firstUncoveredSet(sets []ds.Set[ID], chosen ds.MutableSet[ID]) (ds.Set[ID], bool) {
	for _, s := range sets {
		hit := false
		for id := range s.Iter() {
			if chosen.Contains(id) {
				hit = true
				break
			}
		}
		if !hit {
			return s, true
		}
	}
	return nil, false
}

func canStillHitAllSets(sets []ds.Set[ID], chosen, excluded ds.MutableSet[ID]) bool {
	for _, s := range sets {
		hit := false
		hasCandidate := false
		for id := range s.Iter() {
			if chosen.Contains(id) {
				hit = true
				break
			}
			if !excluded.Contains(id) {
				hasCandidate = true
			}
		}
		if !hit && !hasCandidate {
			return false
		}
	}
	return true
}

func allChosenHaveCritical(sets []ds.Set[ID], chosen ds.MutableSet[ID]) bool {
	for id := range chosen.Iter() {
		hasCritical := false
		for _, s := range sets {
			if !s.Contains(id) {
				continue
			}

			isCritical := true
			for other := range chosen.Iter() {
				if other == id {
					continue
				}
				if s.Contains(other) {
					isCritical = false
					break
				}
			}
			if isCritical {
				hasCritical = true
				break
			}
		}
		if !hasCritical {
			return false
		}
	}
	return true
}

func complementSet(universe ds.Set[ID], chosen ds.MutableSet[ID]) ds.Set[ID] {
	out := hashset.NewComparable[ID]()
	for id := range universe.Iter() {
		if !chosen.Contains(id) {
			out.Add(id)
		}
	}
	return out.Freeze()
}
