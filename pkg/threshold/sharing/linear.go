package sharing

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/errs-go/errs"
)

type (
	// DNFAccessStructure represents an access structure in disjunctive normal form, defined by its minimal qualified subsets.
	DNFAccessStructure []ds.Set[ID]
	// CNFAccessStructure represents an access structure in conjunctive normal form, defined by its maximal unqualified subsets.
	CNFAccessStructure []ds.Set[ID]
)

type dnfAccessStructureDTO struct {
	ps []map[ID]bool `cbor:"authorizedSubsets"`
}

type cnfAccessStructureDTO struct {
	ps []map[ID]bool `cbor:"unauthorizedSubsets"`
}

// NewDNFAccessStructure creates a new DNF access structure from the given minimal qualified subsets.
func NewDNFAccessStructure(minimalQualifiedSets ...ds.Set[ID]) (DNFAccessStructure, error) {
	if err := validateISNAccessStructure(minimalQualifiedSets...); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid minimal qualified sets")
	}
	return DNFAccessStructure(minimalQualifiedSets), nil
}

// NewCNFAccessStructure creates a new CNF access structure from the given maximal unqualified subsets.
func NewCNFAccessStructure(maximalUnqualifiedSets ...ds.Set[ID]) (CNFAccessStructure, error) {
	if err := validateISNAccessStructure(maximalUnqualifiedSets...); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid maximal unqualified sets")
	}
	return CNFAccessStructure(maximalUnqualifiedSets), nil
}

func validateISNAccessStructure(minimalQualifiedOrMaximalUnqualifiedSets ...ds.Set[ID]) error {
	if minimalQualifiedOrMaximalUnqualifiedSets == nil {
		return ErrIsNil.WithMessage("minimal qualified sets is nil")
	}
	if len(minimalQualifiedOrMaximalUnqualifiedSets) == 0 {
		return ErrValue.WithMessage("must have at least one minimal qualified set")
	}
	for i, si := range minimalQualifiedOrMaximalUnqualifiedSets {
		if si == nil {
			return ErrIsNil.WithMessage("set at index %d is nil", i)
		}
		if si.Size() == 0 {
			return ErrValue.WithMessage("set at index %d is empty", i)
		}
		for j := i + 1; j < len(minimalQualifiedOrMaximalUnqualifiedSets); j++ {
			sj := minimalQualifiedOrMaximalUnqualifiedSets[j]

			if si.Equal(sj) {
				return ErrValue.WithMessage("sets at indices %d and %d are equal", i, j)
			}
			if si.IsSubSet(sj) {
				return ErrValue.WithMessage("set at index %d is a subset of set at index %d", i, j)
			}
			if sj.IsSubSet(si) {
				return ErrValue.WithMessage("set at index %d is a subset of set at index %d", j, i)
			}

		}
	}
	return nil
}

// Shareholders returns the set of all shareholder IDs appearing in any minimal qualified set.
func (d DNFAccessStructure) Shareholders() ds.Set[ID] {
	shareholders := hashset.NewComparable[ID]()
	for _, subset := range d {
		for id := range subset.Iter() {
			shareholders.Add(id)
		}
	}
	return shareholders.Freeze()
}

// Shareholders returns the set of all shareholder IDs appearing in any maximal unqualified set.
func (c CNFAccessStructure) Shareholders() ds.Set[ID] {
	shareholders := hashset.NewComparable[ID]()
	for _, subset := range c {
		for id := range subset.Iter() {
			shareholders.Add(id)
		}
	}
	return shareholders.Freeze()
}

// IsAuthorized checks if the given IDs form an authorized coalition according to the DNF access structure.
// A coalition is authorized if it contains at least one of the minimal qualified subsets.
func (d DNFAccessStructure) IsAuthorized(ids ...ID) bool {
	idSet := hashset.NewComparable(ids...).Freeze()
	for _, subset := range d {
		if subset.IsSubSet(idSet) {
			return true
		}
	}
	return false
}

// IsAuthorized checks if the given IDs form an authorized coalition according to the CNF access structure.
// A coalition is authorized if it does not contain any of the maximal unqualified subsets.
func (c CNFAccessStructure) IsAuthorized(ids ...ID) bool {
	idSet := hashset.NewComparable(ids...).Freeze()
	for _, u := range c {
		if idSet.IsSubSet(u) {
			return false
		}
	}
	return true
}

func (d DNFAccessStructure) MarshalCBOR() ([]byte, error) {
	dto := dnfAccessStructureDTO{
		ps: make([]map[ID]bool, len(d)),
	}
	for i, subset := range d {
		dto.ps[i] = make(map[ID]bool)
		for id := range subset.Iter() {
			dto.ps[i][id] = true
		}
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return data, nil
}

func (d *DNFAccessStructure) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[dnfAccessStructureDTO](data)
	if err != nil {
		return errs.Wrap(err)
	}
	ps := make([]ds.Set[ID], len(dto.ps))
	for i, subsetMap := range dto.ps {
		subset := hashset.NewComparable[ID]()
		for id := range subsetMap {
			subset.Add(id)
		}
		ps[i] = subset.Freeze()
	}
	*d = DNFAccessStructure(ps)
	return nil
}

func (c CNFAccessStructure) MarshalCBOR() ([]byte, error) {
	dto := cnfAccessStructureDTO{
		ps: make([]map[ID]bool, len(c)),
	}
	for i, subset := range c {
		dto.ps[i] = make(map[ID]bool)
		for id := range subset.Iter() {
			dto.ps[i][id] = true
		}
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return data, nil
}

func (c *CNFAccessStructure) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[cnfAccessStructureDTO](data)
	if err != nil {
		return errs.Wrap(err)
	}
	ps := make([]ds.Set[ID], len(dto.ps))
	for i, subsetMap := range dto.ps {
		subset := hashset.NewComparable[ID]()
		for id := range subsetMap {
			subset.Add(id)
		}
		ps[i] = subset.Freeze()
	}
	*c = CNFAccessStructure(ps)
	return nil
}

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
		return nil, ErrIsNil.WithMessage("ids cannot be nil")
	}
	if shareholders.Size() < 2 {
		return nil, ErrValue.WithMessage("ids must have at least 2 shareholders")
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
		return nil, errs.Wrap(err)
	}
	return data, nil
}

func (a *MinimalQualifiedAccessStructure) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[minimalQualifiedAccessStructureDTO](data)
	if err != nil {
		return errs.Wrap(err)
	}
	ps := hashset.NewComparable[ID]()
	for id := range dto.Ps {
		ps.Add(id)
	}
	a.ps = ps.Freeze()
	return nil
}
