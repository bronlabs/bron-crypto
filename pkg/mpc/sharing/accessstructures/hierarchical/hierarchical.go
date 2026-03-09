package hierarchical

import (
	"iter"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
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

type hierarchicalConjunctiveThresholdDTO struct {
	Levels []*ThresholdLevel `json:"levels"`
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

// MarshalCBOR serialises the hierarchical access structure.
func (h *HierarchicalConjunctiveThreshold) MarshalCBOR() ([]byte, error) {
	dto := hierarchicalConjunctiveThresholdDTO{
		Levels: h.levels,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal HierarchicalConjunctiveThreshold")
	}
	return out, nil
}

// UnmarshalCBOR deserializes the hierarchical access structure.
func (h *HierarchicalConjunctiveThreshold) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[hierarchicalConjunctiveThresholdDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal HierarchicalConjunctiveThreshold")
	}
	hh, err := NewHierarchicalConjunctiveThresholdAccessStructure(dto.Levels...)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid data for HierarchicalConjunctiveThreshold")
	}
	h.levels = hh.levels
	return nil
}

// ThresholdLevel defines one hierarchical level with a cumulative threshold and
// level-local shareholders.
type ThresholdLevel struct {
	threshold int
	parties   []ID
}

type thresholdLevelDTO struct {
	Threshold int  `json:"threshold"`
	Parties   []ID `json:"parties"`
}

// Threshold returns the cumulative threshold of the level.
func (l *ThresholdLevel) Threshold() int {
	return l.threshold
}

// Shareholders returns shareholders assigned to this level.
func (l *ThresholdLevel) Shareholders() ds.Set[ID] {
	return hashset.NewComparable(l.parties...).Freeze()
}

// MarshalCBOR serialises the threshold level.
func (l *ThresholdLevel) MarshalCBOR() ([]byte, error) {
	dto := thresholdLevelDTO{
		Threshold: l.threshold,
		Parties:   l.parties,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal ThresholdLevel")
	}
	return out, nil
}

// UnmarshalCBOR deserializes the threshold level.
func (l *ThresholdLevel) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[thresholdLevelDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal ThresholdLevel")
	}
	l.threshold = dto.Threshold
	l.parties = dto.Parties
	return nil
}

// func BuildMatrix[E algebra.PrimeFieldElement[E]](field algebra.PrimeField[E], ac *HierarchicalConjunctiveThreshold, quorum ds.Set[ID]) (*mat.SquareMatrix[E], error) {
// 	sortedQuorum := quorum.List()
// 	slices.Sort(sortedQuorum)

// 	var eyes []E
// 	var jays []uint64
// 	for _, id := range sortedQuorum {
// 		eyes = append(eyes, field.FromUint64(uint64(id)))
// 		j, ok := Rank(ac, id)
// 		if !ok {
// 			return nil, ErrMembership.WithMessage("invalid shareholder ID %d", id)
// 		}
// 		jays = append(jays, uint64(j))
// 	}
// 	m, err := birkhoff.BuildVandermondeMatrix(eyes, jays)
// 	if err != nil {
// 		return nil, errs.Wrap(err).WithMessage("could not create birkhoff matrix")
// 	}
// 	return m, nil
// }.

// func Rank(accessStructure *HierarchicalConjunctiveThreshold, id ID) (int, bool) {
// 	if accessStructure == nil {
// 		return 0, false
// 	}
// 	r := 0
// 	for _, level := range accessStructure.Levels() {
// 		if level.Shareholders().Contains(id) {
// 			return r, true
// 		}
// 		r = level.Threshold()
// 	}
// 	return 0, false
// }.

// InducedMSPByHierarchicalConjunctiveThreshold constructs a monotone span
// programme from a hierarchical conjunctive threshold access structure.
// Not yet implemented.
func InducedMSPByHierarchicalConjunctiveThreshold[E algebra.PrimeFieldElement[E]](f algebra.PrimeField[E], ac *HierarchicalConjunctiveThreshold) (*msp.MSP[E], error) {
	panic("not implemented")
}
