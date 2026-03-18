package unanimity

import (
	"iter"
	"maps"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/cnf"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/internal"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
)

// ID uniquely identifies a shareholder.
type ID = internal.ID

// Unanimity represents an n-of-n access structure where
// all shareholders must participate to reconstruct the secret. This is the
// access structure for additive secret sharing.
type Unanimity struct {
	ps ds.Set[ID]
}

type unanimityDTO struct {
	Ps map[ID]bool `cbor:"shareholders"`
}

// NewUnanimityAccessStructure creates a new n-of-n access structure.
//
// Parameters:
//   - shareholders: The set of shareholder IDs (must have at least 2 members)
//
// Returns an error if shareholders is nil or has fewer than 2 members.
func NewUnanimityAccessStructure(shareholders ds.Set[ID]) (*Unanimity, error) {
	if shareholders == nil {
		return nil, ErrIsNil.WithMessage("ids cannot be nil")
	}
	if shareholders.Size() < 2 {
		return nil, ErrValue.WithMessage("ids must have at least 2 shareholders")
	}
	if shareholders.Contains(0) {
		return nil, ErrMembership.WithMessage("shareholders cannot contain 0")
	}

	return &Unanimity{
		ps: shareholders,
	}, nil
}

// IsQualified reports whether ids equal the full shareholder set.
func (u *Unanimity) IsQualified(ids ...ID) bool {
	if u == nil || u.ps == nil {
		return false
	}
	idSet := hashset.NewComparable(ids...).Freeze()
	return idSet.Equal(u.ps)
}

// Shareholders returns the full shareholder set.
func (u *Unanimity) Shareholders() ds.Set[ID] {
	return u.ps
}

// MaximalUnqualifiedSetsIter streams all size-(n-1) subsets.
func (u *Unanimity) MaximalUnqualifiedSetsIter() iter.Seq[ds.Set[ID]] {
	return func(yield func(ds.Set[ID]) bool) {
		for c := range sliceutils.Combinations(u.ps.List(), uint(u.ps.Size()-1)) {
			s := hashset.NewComparable(c...)
			if cont := yield(s.Freeze()); !cont {
				break
			}
		}
	}
}

// Equal returns true if two access structures have the same shareholders.
func (u *Unanimity) Equal(other *Unanimity) bool {
	if u == nil || other == nil {
		return u == other
	}
	if u.ps.Size() != other.ps.Size() {
		return false
	}
	return u.ps.Equal(other.ps)
}

// Clone returns a deep copy of this access structure.
func (u *Unanimity) Clone() *Unanimity {
	if u == nil {
		return nil
	}
	return &Unanimity{
		ps: u.ps.Clone(),
	}
}

// MarshalCBOR serialises the access structure.
func (u *Unanimity) MarshalCBOR() ([]byte, error) {
	dto := unanimityDTO{
		Ps: make(map[ID]bool),
	}
	for id := range u.ps.Iter() {
		dto.Ps[id] = true
	}
	data, err := serde.MarshalCBOR(dto)
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

// InducedMSP constructs a monotone span programme from a unanimity
// access structure by converting to CNF form.
func InducedMSP[E algebra.PrimeFieldElement[E]](f algebra.PrimeField[E], ac *Unanimity) (*msp.MSP[E], error) {
	if f == nil {
		return nil, ErrIsNil.WithMessage("field cannot be nil")
	}
	if ac == nil {
		return nil, ErrIsNil.WithMessage("access structure cannot be nil")
	}
	// For unanimity with n shareholders, the CNF has n maximal unqualified sets,
	// each clause is a singleton, so MSP has n rows and n columns, which is already minimal.
	ascnf, err := cnf.ConvertToCNF(ac)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to convert unanimity to CNF")
	}
	out, err := cnf.InducedMSP(f, ascnf)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to induce MSP from CNF conversion of unanimity")
	}
	return out, nil
}
