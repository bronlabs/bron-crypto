package sharing

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

// MinimalQualifiedAccessStructure represents an n-of-n access structure where
// all shareholders must participate to reconstruct the secret. This is the
// access structure for additive secret sharing.
type MinimalQualifiedAccessStructure struct {
	ps ds.Set[ID]
}

type minimalQualifiedAccessStructureDTO struct {
	Ps map[ID]bool `cbor:"shareholders"`
}

// NewMinimalQualifiedAccessStructure creates a new n-of-n access structure.
//
// Parameters:
//   - shareholders: The set of shareholder IDs (must have at least 2 members)
//
// Returns an error if shareholders is nil or has fewer than 2 members.
func NewMinimalQualifiedAccessStructure(shareholders ds.Set[ID]) (*MinimalQualifiedAccessStructure, error) {
	if shareholders == nil {
		return nil, errs.NewIsNil("ids cannot be nil")
	}
	if shareholders.Size() < 2 {
		return nil, errs.NewValue("ids must have at least 2 shareholders")
	}
	return &MinimalQualifiedAccessStructure{
		ps: shareholders,
	}, nil
}

// Shareholders returns the set of all shareholder IDs.
func (a *MinimalQualifiedAccessStructure) Shareholders() ds.Set[ID] {
	return a.ps
}

// IsAuthorized returns true only if the given IDs exactly match all shareholders.
// Unlike threshold access structures, partial subsets are never authorized.
func (a *MinimalQualifiedAccessStructure) IsAuthorized(ids ...ID) bool {
	return a.ps.Size() == len(ids) && a.ps.Equal(hashset.NewComparable(ids...).Freeze())
}

func (a *MinimalQualifiedAccessStructure) MarshalCBOR() ([]byte, error) {
	dto := minimalQualifiedAccessStructureDTO{
		Ps: make(map[ID]bool),
	}
	for id := range a.ps.Iter() {
		dto.Ps[id] = true
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return data, nil
}

func (a *MinimalQualifiedAccessStructure) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[minimalQualifiedAccessStructureDTO](data)
	if err != nil {
		return errs2.Wrap(err)
	}
	ps := hashset.NewComparable[ID]()
	for id := range dto.Ps {
		ps.Add(id)
	}
	a.ps = ps.Freeze()
	return nil
}
