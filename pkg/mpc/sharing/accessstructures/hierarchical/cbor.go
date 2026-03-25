package hierarchical

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/internal/tags"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

const HierarchicalConjunctiveThresholdAccessStructureTag = tags.HierarchicalConjunctiveThresholdAccessStructureTag

func init() {
	serde.Register[*HierarchicalConjunctiveThreshold](HierarchicalConjunctiveThresholdAccessStructureTag)
}

type hierarchicalConjunctiveThresholdDTO struct {
	Levels []*ThresholdLevel `cbor:"levels"`
}

// MarshalCBOR serialises the hierarchical access structure.
func (h *HierarchicalConjunctiveThreshold) MarshalCBOR() ([]byte, error) {
	dto := hierarchicalConjunctiveThresholdDTO{
		Levels: h.levels,
	}
	out, err := serde.MarshalCBORTagged(dto, HierarchicalConjunctiveThresholdAccessStructureTag)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal HierarchicalConjunctiveThreshold")
	}
	return out, nil
}

// UnmarshalCBOR deserializes the hierarchical access structure.
func (h *HierarchicalConjunctiveThreshold) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*hierarchicalConjunctiveThresholdDTO](data)
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

type thresholdLevelDTO struct {
	Threshold int  `cbor:"threshold"`
	Parties   []ID `cbor:"parties"`
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
	if dto.Threshold <= 0 {
		return ErrValue.WithMessage("threshold must be positive")
	}
	if len(dto.Parties) == 0 {
		return ErrValue.WithMessage("parties must not be empty")
	}
	for _, p := range dto.Parties {
		if p == 0 {
			return ErrValue.WithMessage("parties cannot contain shareholder ID 0")
		}
	}
	l.threshold = dto.Threshold
	l.parties = dto.Parties
	return nil
}
