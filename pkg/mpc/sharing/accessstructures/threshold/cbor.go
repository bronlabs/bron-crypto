package threshold

import (
	"maps"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/internal/tags"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

const ThresholdAccessStructureTag = tags.ThresholdAccessStructureTag

func init() {
	serde.Register[*Threshold](ThresholdAccessStructureTag)
}

type thresholdDTO struct {
	T  uint        `cbor:"threshold"`
	Ps map[ID]bool `cbor:"shareholders"`
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

	data, err := serde.MarshalCBORTagged(dto, ThresholdAccessStructureTag)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal AccessStructure")
	}
	return data, nil
}

// UnmarshalCBOR deserializes the threshold access structure.
func (a *Threshold) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*thresholdDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal Threshold access structure")
	}
	ps := hashset.NewComparable(slices.Collect(maps.Keys(dto.Ps))...)

	a2, err := NewThresholdAccessStructure(dto.T, ps.Freeze())
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create Threshold access structure from deserialized data")
	}

	*a = *a2
	return nil
}
