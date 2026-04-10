package unanimity

import (
	"iter"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
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

// InducedMSP constructs the ideal monotone span programme for additive sharing.
// For n shareholders, the MSP is an n×n matrix with 1s on the superdiagonal and
// a last row equal to (1, -1, -1, ..., -1).
func InducedMSP[E algebra.PrimeFieldElement[E]](f algebra.PrimeField[E], ac *Unanimity) (*msp.MSP[E], error) {
	if f == nil {
		return nil, ErrIsNil.WithMessage("field cannot be nil")
	}
	if ac == nil {
		return nil, ErrIsNil.WithMessage("access structure cannot be nil")
	}
	shareholders := ac.Shareholders().List()
	slices.Sort(shareholders)

	n := len(shareholders)
	module, err := mat.NewMatrixModule(uint(n), uint(n), f)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create matrix module for unanimity MSP")
	}

	values := make([]E, n*n)
	one := f.One()
	minusOne := one.OpInv()
	zero := f.Zero()
	for i := range values {
		values[i] = zero
	}
	for row := range n - 1 {
		values[row*n+row+1] = one
	}
	values[(n-1)*n] = one
	for col := 1; col < n; col++ {
		values[(n-1)*n+col] = minusOne
	}

	matrix, err := module.NewRowMajor(values...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to build unanimity MSP matrix")
	}

	rowsToHolders := make(map[int]ID, n)
	for i, id := range shareholders {
		rowsToHolders[i] = id
	}
	out, err := msp.NewMSP(matrix, rowsToHolders)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create MSP from unanimity access structure")
	}
	return out, nil
}
