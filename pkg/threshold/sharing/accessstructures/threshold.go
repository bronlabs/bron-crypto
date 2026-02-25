package accessstructures

import (
	"iter"
	"maps"
	"slices"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/errs-go/errs"
)

var _ Monotone = (*Threshold)(nil)

// Threshold represents a (t,n) threshold access structure where
// any subset of at least t shareholders (out of n total) is authorized to
// reconstruct the secret.
type Threshold struct {
	t  uint
	ps ds.Set[ID]
}

type thresholdDTO struct {
	T  uint        `cbor:"threshold"`
	Ps map[ID]bool `cbor:"shareholders"`
}

// NewThresholdAccessStructure creates a new threshold access structure.
//
// Parameters:
//   - t: The threshold (minimum shares required), must be at least 2
//   - ps: The set of shareholder IDs, must not contain 0
//
// Returns an error if t < 2, t > |ps|, ps is nil, or ps contains 0.
func NewThresholdAccessStructure(t uint, ps ds.Set[ID]) (*Threshold, error) {
	if ps == nil {
		return nil, ErrIsNil.WithMessage("party set is nil")
	}
	if ps.Contains(0) {
		return nil, ErrMembership.WithMessage("party set cannot contain 0")
	}
	if t < 2 {
		return nil, ErrValue.WithMessage("threshold cannot be less than 2")
	}
	if t > uint(ps.Size()) {
		return nil, ErrValue.WithMessage("total cannot be less than threshold")
	}
	return &Threshold{
		t:  t,
		ps: ps,
	}, nil
}

// ThresholdAccessStructure returns the minimum number of shares required for reconstruction.
func (a *Threshold) Threshold() uint {
	return a.t
}

// Shareholders returns the set of all valid shareholder IDs.
func (a *Threshold) Shareholders() ds.Set[ID] {
	return a.ps
}

// IsQualified returns true if the given set of shareholder IDs forms an
// authorized subset (i.e., has at least t members, all from the shareholder set).
func (a *Threshold) IsQualified(ids ...ID) bool {
	idsSet := hashset.NewComparable(ids...).Freeze()
	return idsSet.Size() >= int(a.t) &&
		idsSet.IsSubSet(a.ps)
}

// MaximalUnqualifiedSetsIter streams all size-(t-1) subsets of shareholders.
func (a *Threshold) MaximalUnqualifiedSetsIter() iter.Seq[ds.Set[ID]] {
	return func(yield func(ds.Set[ID]) bool) {
		for c := range sliceutils.Combinations(a.ps.List(), a.t-1) {
			s := hashset.NewComparable[ID](c...)
			if cont := yield(s.Freeze()); !cont {
				break
			}
		}
	}
}

// Equal returns true if two access structures have the same threshold and shareholders.
func (a *Threshold) Equal(other *Threshold) bool {
	if a == nil || other == nil {
		return a == other
	}
	if a.t != other.t {
		return false
	}
	if a.ps.Size() != other.ps.Size() {
		return false
	}
	return a.ps.Equal(other.ps)
}

// Clone returns a deep copy of this access structure.
func (a *Threshold) Clone() *Threshold {
	if a == nil {
		return nil
	}
	return &Threshold{
		t:  a.t,
		ps: a.ps.Clone(),
	}
}

// MarshalCBOR serialises the threshold access structure.
func (a *Threshold) MarshalCBOR() ([]byte, error) {
	dto := &thresholdDTO{
		T:  a.t,
		Ps: make(map[ID]bool),
	}
	for p := range a.ps.Iter() {
		dto.Ps[p] = true
	}

	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal AccessStructure")
	}
	return data, nil
}

// UnmarshalCBOR deserializes the threshold access structure.
func (a *Threshold) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*thresholdDTO](data)
	if err != nil {
		return err
	}
	ps := hashset.NewComparable(slices.Collect(maps.Keys(dto.Ps))...)

	a2, err := NewThresholdAccessStructure(dto.T, ps.Freeze())
	if err != nil {
		return err
	}

	*a = *a2
	return nil
}
