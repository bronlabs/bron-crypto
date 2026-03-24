package cnf

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/internal/tags"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

const CNFAccessStructureTag = tags.CNFAccessStructureTag

func init() {
	serde.Register[*CNF](CNFAccessStructureTag)
}

type cnfDTO struct {
	Shareholders           map[ID]bool   `cbor:"shareholders"`
	MaximalUnqualifiedSets []map[ID]bool `cbor:"maximal_unqualified_sets"`
}

// MarshalCBOR serialises the CNF access structure.
func (c *CNF) MarshalCBOR() ([]byte, error) {
	dto := &cnfDTO{
		Shareholders:           make(map[ID]bool),
		MaximalUnqualifiedSets: make([]map[ID]bool, len(c.maximalUnqualifiedSets)),
	}
	for p := range c.shareholders.Iter() {
		dto.Shareholders[p] = true
	}
	for i, u := range c.maximalUnqualifiedSets {
		dto.MaximalUnqualifiedSets[i] = make(map[ID]bool)
		for p := range u.Iter() {
			dto.MaximalUnqualifiedSets[i][p] = true
		}
	}

	data, err := serde.MarshalCBORTagged(dto, CNFAccessStructureTag)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal CNF access structure")
	}
	return data, nil
}

// UnmarshalCBOR deserializes the CNF access structure.
func (c *CNF) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*cnfDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal CNF access structure")
	}

	maximalUnqualifiedSets := make([]ds.Set[ID], len(dto.MaximalUnqualifiedSets))
	for i, u := range dto.MaximalUnqualifiedSets {
		setBuilder := hashset.NewComparable[ID]()
		for p := range u {
			setBuilder.Add(p)
		}
		maximalUnqualifiedSets[i] = setBuilder.Freeze()
	}

	a2, err := NewCNFAccessStructure(maximalUnqualifiedSets...)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create CNF access structure from unmarshalled data")
	}
	*c = *a2
	return nil
}
