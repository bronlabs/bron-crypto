package cnf

import (
	"cmp"
	"iter"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/bitset"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/internal"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
)

// ID uniquely identifies a shareholder.
type ID = internal.ID

// CNF represents a monotone access structure via maximal
// unqualified clauses in conjunctive normal form.
type CNF struct {
	shareholders           ds.Set[ID]
	maximalUnqualifiedSets []ds.Set[ID]
}

type cnfDTO struct {
	Shareholders           map[ID]bool   `cbor:"shareholders"`
	MaximalUnqualifiedSets []map[ID]bool `cbor:"maximal_unqualified_sets"`
}

// ConvertToCNF converts a linear access structure to CNF form by enumerating its maximal unqualified sets.
// This may be inefficient for access structures with many maximal unqualified sets, so use with caution.
func ConvertToCNF(ac interface {
	Shareholders() ds.Set[ID]
	MaximalUnqualifiedSetsIter() iter.Seq[ds.Set[ID]]
}) (*CNF, error) {
	if ac == nil {
		return nil, ErrIsNil.WithMessage("access structure cannot be nil")
	}
	return &CNF{
		shareholders:           ac.Shareholders(),
		maximalUnqualifiedSets: slices.Collect(ac.MaximalUnqualifiedSetsIter()),
	}, nil
}

// NewCNFAccessStructure constructs a CNF access structure from unqualified sets
// and normalises them into unique maximal clauses.
func NewCNFAccessStructure(unqualifiedSets ...ds.Set[ID]) (*CNF, error) {
	maximalUnqualifiedSets, err := normaliseCNF(unqualifiedSets...)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	shareholders := hashset.NewComparable[ID]()
	for _, u := range maximalUnqualifiedSets {
		shareholders.AddAll(u.List()...)
	}
	if shareholders.Size() < 2 {
		return nil, ErrMembership.WithMessage("shareholders must be a set of at least 2 distinct IDs, excluding 0")
	}

	c := &CNF{
		shareholders:           shareholders.Freeze(),
		maximalUnqualifiedSets: maximalUnqualifiedSets,
	}
	return c, nil
}

// IsQualified reports whether ids satisfy the CNF access policy.
func (c *CNF) IsQualified(ids ...ID) bool {
	if c == nil || c.shareholders == nil {
		return false
	}

	idSet := hashset.NewComparable(ids...).Freeze()
	if !idSet.IsSubSet(c.shareholders) {
		return false
	}
	for _, u := range c.maximalUnqualifiedSets {
		if idSet.IsSubSet(u) {
			return false
		}
	}
	return true
}

// Shareholders returns the shareholder universe for this access structure.
func (c *CNF) Shareholders() ds.Set[ID] {
	return c.shareholders
}

// MaximalUnqualifiedSetsIter streams maximal unqualified sets.
func (c *CNF) MaximalUnqualifiedSetsIter() iter.Seq[ds.Set[ID]] {
	if c == nil || len(c.maximalUnqualifiedSets) == 0 {
		return slices.Values([]ds.Set[ID]{})
	}
	return slices.Values(c.maximalUnqualifiedSets)
}

// Clauses returns the CNF clauses corresponding to the maximal unqualified sets.
func (c *CNF) Clauses() []ds.Set[ID] {
	return sliceutils.Map(
		c.maximalUnqualifiedSets,
		func(bi ds.Set[ID]) ds.Set[ID] {
			return c.shareholders.Difference(bi)
		},
	)
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

	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal CNF access structure")
	}
	return data, nil
}

// UnmarshalCBOR deserializes the CNF access structure.
func (c *CNF) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[cnfDTO](data)
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

func normaliseCNF(unqualifiedSets ...ds.Set[ID]) ([]ds.Set[ID], error) {
	if len(unqualifiedSets) == 0 {
		return nil, ErrValue.WithMessage("must have at least one unqualified set")
	}

	uniqueSets := make([]ds.Set[ID], 0, len(unqualifiedSets))
	for _, s := range unqualifiedSets {
		if s == nil {
			return nil, ErrIsNil.WithMessage("unqualified set cannot be nil")
		}
		if s.IsEmpty() {
			return nil, ErrValue.WithMessage("unqualified set cannot be empty")
		}
		if s.Contains(0) {
			return nil, ErrMembership.WithMessage("unqualified set cannot contain shareholder ID 0")
		}
		normalised := hashset.NewComparable(s.List()...).Freeze()

		alreadySeen := false
		for _, seen := range uniqueSets {
			if normalised.Equal(seen) {
				alreadySeen = true
				break
			}
		}
		if !alreadySeen {
			uniqueSets = append(uniqueSets, normalised)
		}
	}

	maximalSets := make([]ds.Set[ID], 0, len(uniqueSets))
	for i, si := range uniqueSets {
		isMaximal := true
		for j, sj := range uniqueSets {
			if i == j {
				continue
			}
			if si.IsSubSet(sj) {
				isMaximal = false
				break
			}
		}
		if isMaximal {
			maximalSets = append(maximalSets, si)
		}
	}

	return maximalSets, nil
}

// InducedMSP constructs a monotone span programme from a CNF access
// structure. Each clause yields one block of rows, one per clause member.
func InducedMSP[E algebra.PrimeFieldElement[E]](f algebra.PrimeField[E], c *CNF) (*msp.MSP[E], error) {
	if f == nil {
		return nil, ErrIsNil.WithMessage("field cannot be nil")
	}
	if c == nil {
		return nil, ErrIsNil.WithMessage("access structure cannot be nil")
	}

	// Sort maximal unqualified sets into a canonical order so that every caller
	// (potentially running in separate processes) produces the same MSP matrix
	// and row-to-holder mapping. Without this, Go map-iteration
	// non-determinism inside hash-set List()/Iter() would cause different
	// participants to disagree on the MSP row assignments, breaking share
	// verification in protocols that independently reconstruct the MSP
	// (e.g. Gennaro DKG over KW).
	sortedMUS := slices.Clone(c.maximalUnqualifiedSets)
	slices.SortFunc(sortedMUS, func(a, b ds.Set[ID]) int {
		ba := bitset.NewImmutableBitSet(a.List()...)
		bb := bitset.NewImmutableBitSet(b.List()...)
		return cmp.Compare(uint64(ba), uint64(bb))
	})

	m := len(sortedMUS)
	clauses := sliceutils.Map(sortedMUS, func(bi ds.Set[ID]) ds.Set[ID] {
		return c.shareholders.Difference(bi)
	})

	// Compute total number of rows (one per shareholder-clause membership).
	totalRows := 0
	for _, cl := range clauses {
		totalRows += cl.Size()
	}

	matrixFactory, err := mat.NewMatrixModule(uint(totalRows), uint(m), f)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create matrix factory for MSP induction")
	}

	clauseVectors := make([]*mat.Matrix[E], m)
	clauseVectors[m-1], err = matrixFactory.NewStandardUnit(0) // this will be e0 - e1 - ... - e_{m-2}
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create clause vector for MSP induction")
	}
	for i := range m - 1 {
		clauseVectors[i], err = matrixFactory.NewStandardUnit(i + 1)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to create clause vector for MSP induction")
		}
		clauseVectors[m-1].SubAssign(clauseVectors[i])
	}

	rowsInRowMajorForm := []E{}
	rowsToHolders := make(map[int]ID)
	rowIdx := 0
	for i := range m {
		// Sort clause members for deterministic row-to-holder assignment.
		members := clauses[i].List()
		slices.Sort(members)
		for _, pi := range members {
			rowsInRowMajorForm = append(rowsInRowMajorForm, slices.Collect(clauseVectors[i].Iter())...)
			rowsToHolders[rowIdx] = pi
			rowIdx++
		}
	}

	matrix, err := matrixFactory.NewRowMajor(rowsInRowMajorForm...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create matrix for MSP induction")
	}

	out, err := msp.NewMSP(matrix, rowsToHolders)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create MSP from CNF access structure")
	}
	return out, nil
}
