package accessstructures

import (
	"iter"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
)

var _ Monotone = (*HierarchicalConjunctiveThreshold)(nil)

// WithLevel constructs a hierarchical threshold level.
//
// The threshold is cumulative across this level and all previous levels.
func WithLevel(threshold int, parties ...ID) *ThresholdLevel {
	return &ThresholdLevel{threshold, parties}
}

// HierarchicalConjunctiveThreshold is a monotone access
// structure composed of ordered levels and strictly increasing cumulative
// thresholds.
type HierarchicalConjunctiveThreshold struct {
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
func NewHierarchicalConjunctiveThresholdAccessStructure(levels ...*ThresholdLevel) (*HierarchicalConjunctiveThreshold, error) {
	if len(levels) < 1 {
		return nil, ErrValue.WithMessage("at least 1 level required")
	}

	var ls []*ThresholdLevel
	cumulativeParties := hashset.NewComparable[ID]()
	currentThreshold := 0
	for _, l := range levels {
		parties := hashset.NewComparable(l.parties...)
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

	h := &HierarchicalConjunctiveThreshold{levels: ls}
	return h, nil
}

// Levels returns levels in policy evaluation order.
func (h *HierarchicalConjunctiveThreshold) Levels() []*ThresholdLevel {
	return h.levels
}

// IsQualified reports whether ids satisfy every cumulative level threshold.
func (h *HierarchicalConjunctiveThreshold) IsQualified(ids ...ID) bool {
	partiesSet := hashset.NewComparable(ids...)
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
func (h *HierarchicalConjunctiveThreshold) Shareholders() ds.Set[ID] {
	shareholders := hashset.NewComparable[ID]()
	for _, level := range h.levels {
		shareholders.AddAll(level.parties...)
	}
	return shareholders.Freeze()
}

// MaximalUnqualifiedSetsIter streams all maximal unqualified sets.
func (*HierarchicalConjunctiveThreshold) MaximalUnqualifiedSetsIter() iter.Seq[ds.Set[ID]] {
	panic("not implemented")
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
	return hashset.NewComparable(l.parties...).Freeze()
}
