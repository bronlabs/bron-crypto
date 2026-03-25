package unanimity

import (
	"maps"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/internal/tags"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

const UnanimityAccessStructureTag = tags.UnanimityAccessStructureTag

func init() {
	serde.Register[*Unanimity](UnanimityAccessStructureTag)
}

type unanimityDTO struct {
	Ps map[ID]bool `cbor:"shareholders"`
}

// MarshalCBOR serialises the access structure.
func (u *Unanimity) MarshalCBOR() ([]byte, error) {
	dto := unanimityDTO{
		Ps: make(map[ID]bool),
	}
	for id := range u.ps.Iter() {
		dto.Ps[id] = true
	}
	data, err := serde.MarshalCBORTagged(dto, UnanimityAccessStructureTag)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal Unanimity access structure")
	}
	return data, nil
}

// UnmarshalCBOR deserializes the access structure.
func (u *Unanimity) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[unanimityDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal Unanimity access structure")
	}
	ps := hashset.NewComparable(slices.Collect(maps.Keys(dto.Ps))...)
	u2, err := NewUnanimityAccessStructure(ps.Freeze())
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create Unanimity access structure from deserialized data")
	}
	*u = *u2
	return nil
}
