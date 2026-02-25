package sharing

import (
	"iter"
	"slices"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

var _ MonotoneAccessStructure = (*HierarchicalConjunctiveThresholdAccessStructure)(nil)

// WithLevel constructs a hierarchical threshold level.
//
// The threshold is cumulative across this level and all previous levels.
func WithLevel(threshold int, parties ...ID) *ThresholdLevel {
	return &ThresholdLevel{threshold, parties}
}

// HierarchicalConjunctiveThresholdAccessStructure is a monotone access
// structure composed of ordered levels and strictly increasing cumulative
// thresholds.
type HierarchicalConjunctiveThresholdAccessStructure struct {
	levels []*ThresholdLevel
}

// NewHierarchicalConjunctiveThresholdAccessStructure builds a hierarchical
// conjunctive threshold access structure from ordered levels.
//
// Validation rules:
//   - at least one level must be provided
//   - shareholder ID 0 is not allowed
//   - levels must be disjoint
//   - thresholds must be strictly increasing
//   - each threshold must not exceed cumulative parties up to that level
func NewHierarchicalConjunctiveThresholdAccessStructure(levels ...*ThresholdLevel) (*HierarchicalConjunctiveThresholdAccessStructure, error) {
	if len(levels) < 1 {
		return nil, ErrValue.WithMessage("at least 1 level required")
	}

	var ls []*ThresholdLevel
	cumulativeParties := hashset.NewComparable[ID]()
	currentThreshold := 0
	for _, l := range levels {
		parties := hashset.NewComparable[ID](l.parties...)
		if parties.Contains(0) {
			return nil, ErrValue.WithMessage("parties cannot contain shareholder ID 0")
		}

		if l.threshold <= currentThreshold {
			return nil, ErrValue.WithMessage("thresholds must be strictly increasing")
		}
		currentThreshold = l.threshold

		if cumulativeParties.Intersection(parties).Size() > 0 {
			return nil, ErrValue.WithMessage("parties must be disjoint")
		}
		cumulativeParties.AddAll(l.parties...)
		if cumulativeParties.Size() < l.threshold {
			return nil, ErrValue.WithMessage("thresholds must be less than or equal to the number of parties")
		}

		ls = append(ls, &ThresholdLevel{l.threshold, parties.List()})
	}

	h := &HierarchicalConjunctiveThresholdAccessStructure{levels: ls}
	return h, nil
}

// Levels returns levels in policy evaluation order.
func (h *HierarchicalConjunctiveThresholdAccessStructure) Levels() []*ThresholdLevel {
	return h.levels
}

// IsQualified reports whether ids satisfy every cumulative level threshold.
func (h *HierarchicalConjunctiveThresholdAccessStructure) IsQualified(ids ...ID) bool {
	partiesSet := hashset.NewComparable[ID](ids...)
	cumulativeParties := hashset.NewComparable[ID]()
	for _, level := range h.levels {
		cumulativeParties.AddAll(level.parties...)
		if cumulativeParties.Intersection(partiesSet).Size() < level.threshold {
			return false
		}
	}

	return true
}

// Shareholders returns the union of all shareholders across levels.
func (h *HierarchicalConjunctiveThresholdAccessStructure) Shareholders() ds.Set[ID] {
	shareholders := hashset.NewComparable[ID]()
	for _, level := range h.levels {
		shareholders.AddAll(level.parties...)
	}
	return shareholders.Freeze()
}

// MaximalUnqualifiedSetsIter streams all maximal unqualified sets.
func (h *HierarchicalConjunctiveThresholdAccessStructure) MaximalUnqualifiedSetsIter() iter.Seq[ds.Set[ID]] {
	if h == nil || len(h.levels) == 0 {
		return slices.Values([]ds.Set[ID]{})
	}

	levelParties, thresholds := h.normalizedLevels()
	levelCounts := make([]int, len(levelParties))
	cumulative := make([]int, len(levelParties))

	return func(yield func(ds.Set[ID]) bool) {
		var emitConcreteSets func(level int, selected ds.MutableSet[ID]) bool
		emitConcreteSets = func(level int, selected ds.MutableSet[ID]) bool {
			if level == len(levelParties) {
				return yield(selected.Freeze())
			}

			need := levelCounts[level]
			parties := levelParties[level]
			if need == 0 {
				return emitConcreteSets(level+1, selected)
			}

			for comb := range sliceutils.Combinations(parties, uint(need)) {
				selected.AddAll(comb...)
				if !emitConcreteSets(level+1, selected) {
					return false
				}
				selected.RemoveAll(comb...)
			}
			return true
		}

		var recCounts func(level int, prefix int) bool
		recCounts = func(level int, prefix int) bool {
			if level == len(levelParties) {
				if !isMaximalUnqualifiedProfile(levelCounts, cumulative, levelParties, thresholds) {
					return true
				}
				return emitConcreteSets(0, hashset.NewComparable[ID]())
			}

			for count := 0; count <= len(levelParties[level]); count++ {
				levelCounts[level] = count
				cumulative[level] = prefix + count
				if !recCounts(level+1, cumulative[level]) {
					return false
				}
			}
			return true
		}

		_ = recCounts(0, 0)
	}
}

func (h *HierarchicalConjunctiveThresholdAccessStructure) normalizedLevels() (levels [][]ID, thresholds []int) {
	levels = make([][]ID, 0, len(h.levels))
	thresholds = make([]int, 0, len(h.levels))
	seen := hashset.NewComparable[ID]()
	for _, level := range h.levels {
		unique := hashset.NewComparable(level.parties...)
		effective := make([]ID, 0, unique.Size())
		for id := range unique.Iter() {
			if seen.Contains(id) {
				continue
			}
			effective = append(effective, id)
		}
		slices.Sort(effective)
		levels = append(levels, effective)
		thresholds = append(thresholds, level.threshold)
		seen.AddAll(unique.List()...)
	}
	return levels, thresholds
}

func isMaximalUnqualifiedProfile(levelCounts, cumulative []int, levelParties [][]ID, thresholds []int) bool {
	isQualified := true
	for i := range thresholds {
		if cumulative[i] < thresholds[i] {
			isQualified = false
			break
		}
	}
	if isQualified {
		return false
	}

	for level := range levelParties {
		if levelCounts[level] == len(levelParties[level]) {
			continue
		}
		if !qualifiesAfterAddingAtLevel(level, cumulative, thresholds) {
			return false
		}
	}
	return true
}

func qualifiesAfterAddingAtLevel(level int, cumulative, thresholds []int) bool {
	for i := range thresholds {
		count := cumulative[i]
		if i >= level {
			count++
		}
		if count < thresholds[i] {
			return false
		}
	}
	return true
}

// ThresholdLevel defines one hierarchical level with a cumulative threshold and
// level-local shareholders.
type ThresholdLevel struct {
	threshold int
	parties   []ID
}

// Threshold returns the cumulative threshold of the level.
func (l *ThresholdLevel) Threshold() int {
	return l.threshold
}

// Shareholders returns shareholders assigned to this level.
func (l *ThresholdLevel) Shareholders() ds.Set[ID] {
	return hashset.NewComparable[ID](l.parties...).Freeze()
}
