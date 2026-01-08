package sharing

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

// ThresholdAccessStructure represents a (t,n) threshold access structure where
// any subset of at least t shareholders (out of n total) is authorized to
// reconstruct the secret.
type ThresholdAccessStructure struct {
	t  uint
	ps ds.Set[ID]
}

type thresholdAccessStructureDTO struct {
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
func NewThresholdAccessStructure(t uint, ps ds.Set[ID]) (*ThresholdAccessStructure, error) {
	if ps == nil {
		return nil, errs.NewIsNil("party set is nil")
	}
	if ps.Contains(0) {
		return nil, errs.NewMembership("party set cannot contain 0")
	}
	if t < 2 {
		return nil, errs.NewValue("threshold cannot be less than 2")
	}
	if t > uint(ps.Size()) {
		return nil, errs.NewValue("total cannot be less than threshold")
	}
	return &ThresholdAccessStructure{
		t:  t,
		ps: ps,
	}, nil
}

// Threshold returns the minimum number of shares required for reconstruction.
func (a *ThresholdAccessStructure) Threshold() uint {
	return a.t
}

// Shareholders returns the set of all valid shareholder IDs.
func (a *ThresholdAccessStructure) Shareholders() ds.Set[ID] {
	return a.ps
}

// IsAuthorized returns true if the given set of shareholder IDs forms an
// authorized subset (i.e., has at least t members, all from the shareholder set).
func (a *ThresholdAccessStructure) IsAuthorized(ids ...ID) bool {
	idsSet := hashset.NewComparable(ids...)
	return idsSet.Size() >= int(a.t) &&
		idsSet.Size() <= int(a.ps.Size()) &&
		idsSet.Freeze().IsSubSet(a.ps)
}

// Equal returns true if two access structures have the same threshold and shareholders.
func (a *ThresholdAccessStructure) Equal(other *ThresholdAccessStructure) bool {
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
func (a *ThresholdAccessStructure) Clone() *ThresholdAccessStructure {
	if a == nil {
		return nil
	}
	return &ThresholdAccessStructure{
		t:  a.t,
		ps: a.ps.Clone(),
	}
}

func (a *ThresholdAccessStructure) MarshalCBOR() ([]byte, error) {
	dto := &thresholdAccessStructureDTO{
		T:  a.t,
		Ps: make(map[ID]bool),
	}
	for p := range a.ps.Iter() {
		dto.Ps[p] = true
	}

	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal AccessStructure")
	}
	return data, nil
}

func (a *ThresholdAccessStructure) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*thresholdAccessStructureDTO](data)
	if err != nil {
		return err
	}
	ps := hashset.NewComparable[ID]()
	for k, v := range dto.Ps {
		if v {
			ps.Add(k)
		}
	}
	a2, err := NewThresholdAccessStructure(dto.T, ps.Freeze())
	if err != nil {
		return err
	}

	*a = *a2
	return nil
}
