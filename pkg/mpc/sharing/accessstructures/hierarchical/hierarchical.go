package hierarchical

import (
	"iter"
	"math"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation/birkhoff"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/internal"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
)

// ID uniquely identifies a shareholder.
type ID = internal.ID

// WithLevel constructs a hierarchical threshold level.
//
// The threshold is cumulative across this level and all previous levels.
func WithLevel(threshold int, parties ...ID) *ThresholdLevel {
	return &ThresholdLevel{threshold, parties}
}

// HierarchicalConjunctiveThreshold is a monotone access
// structure composed of ordered levels and strictly increasing cumulative
// thresholds.
type HierarchicalConjunctiveThreshold struct { //nolint:revive // keep the Hierarchical prefix for clarity.
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
		if l == nil {
			return nil, ErrIsNil.WithMessage("level cannot be nil")
		}
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
	return slices.Clone(h.levels)
}

func (h *HierarchicalConjunctiveThreshold) Thresholds() []int {
	return sliceutils.Map(h.levels, func(l *ThresholdLevel) int { return l.Threshold() })
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
func (h *HierarchicalConjunctiveThreshold) MaximalUnqualifiedSetsIter() iter.Seq[ds.Set[ID]] {
	if h == nil {
		return slices.Values([]ds.Set[ID]{})
	}
	shareholders := h.Shareholders().List()
	slices.Sort(shareholders)

	maximalUnqualified := make([]ds.Set[ID], 0)
	subset := make([]ID, 0, len(shareholders))
	var enumerate func(int)
	enumerate = func(i int) {
		if i == len(shareholders) {
			if h.IsQualified(subset...) {
				return
			}
			candidate := hashset.NewComparable(subset...).Freeze()
			for j := 0; j < len(maximalUnqualified); {
				switch {
				case candidate.IsSubSet(maximalUnqualified[j]):
					return
				case maximalUnqualified[j].IsSubSet(candidate):
					maximalUnqualified = append(maximalUnqualified[:j], maximalUnqualified[j+1:]...)
				default:
					j++
				}
			}
			maximalUnqualified = append(maximalUnqualified, candidate)
			return
		}

		enumerate(i + 1)
		subset = append(subset, shareholders[i])
		enumerate(i + 1)
		subset = subset[:len(subset)-1]
	}
	enumerate(0)

	return slices.Values(maximalUnqualified)
}

func (h *HierarchicalConjunctiveThreshold) Rank(id ID) (int, error) {
	r := 0
	for _, level := range h.Levels() {
		if level.Shareholders().Contains(id) {
			return r, nil
		}
		r = level.Threshold()
	}
	return 0, ErrMembership.WithMessage("shareholder ID not found")
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

// CheckConstraints verifies that the hierarchical access structure satisfies necessary constraints for the sharing scheme to work correctly.
func CheckConstraints[F algebra.PrimeFieldElement[F]](field algebra.PrimeField[F], ac *HierarchicalConjunctiveThreshold) error {
	if field == nil {
		return ErrIsNil.WithMessage("field cannot be nil")
	}
	if ac == nil {
		return ErrIsNil.WithMessage("access structure cannot be nil")
	}
	// constraint 1: ids from lower level are strictly greater than ids from higher levels
	prevMax := ID(0)
	cummulativeIds := hashset.NewComparable[ID]()
	for _, level := range ac.Levels() {
		for id := range level.Shareholders().Iter() {
			if id <= prevMax {
				return ErrMembership.WithMessage("invalid shareholder ID %d", id)
			}
			cummulativeIds.Add(id)
		}
		allIds := cummulativeIds.List()
		slices.Sort(allIds)
		prevMax = allIds[len(allIds)-1]
	}

	// we increase n and k by one to accommodate "off by one error" caused by precision lost with float64
	n := uint64(prevMax) + 1
	k := uint64(ac.Levels()[len(ac.Levels())-1].Threshold()) + 1
	q, _ := field.Order().Big().Float64()

	// for k > 20, k! overflows uint64. Since we do not work with big enough fields to support such a big k anyway,
	// we reject.
	if k > 20 {
		// this will overflow factorial anyway
		return ErrFailed.WithMessage("too big threshold")
	}

	// constraint 3 (equation 35): α(k)N^((k−1)(k−2)/2) < q = |F| where α(k) := 2^(−k+2) ·(k−1)^((k−1)/2) ·(k−1)!
	alpha := math.Pow(2.0, 2.0-float64(k)) * math.Pow(float64(k-1), (float64(k)-1.0)/2.0) * float64(errs.Must1(mathutils.FactorialUint64(k-1)))
	if (alpha * math.Pow(float64(n), (float64(k)-1.0)*(float64(k)-2)/2.0)) >= q {
		return ErrFailed.WithMessage("constraint failed")
	}

	return nil
}

// InducedMSP constructs a monotone span programme from a hierarchical conjunctive threshold access structure.
func InducedMSP[E algebra.PrimeFieldElement[E]](f algebra.PrimeField[E], ac *HierarchicalConjunctiveThreshold) (*msp.MSP[E], error) {
	if err := CheckConstraints(f, ac); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid access structure for MSP induction")
	}

	shareHolders := ac.Shareholders().List()
	slices.Sort(shareHolders)

	thresholds := ac.Thresholds()
	largestThreshold := thresholds[len(thresholds)-1]

	var eyes []E
	var jays []uint64
	for _, id := range shareHolders {
		eyes = append(eyes, f.FromUint64(uint64(id)))
		j, err := ac.Rank(id)
		if err != nil {
			return nil, ErrMembership.WithMessage("invalid shareholder ID %d", id)
		}
		jays = append(jays, uint64(j))
	}
	matrix, err := birkhoff.BuildVandermondeMatrix(eyes, jays, largestThreshold)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create birkhoff matrix")
	}
	rowsToHolders := make(map[int]ID)
	for i, id := range shareHolders {
		rowsToHolders[i] = id
	}
	out, err := msp.NewMSP(matrix, rowsToHolders)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create MSP from threshold access structure")
	}
	return out, nil
}
