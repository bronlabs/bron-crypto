package threshold

import (
	"iter"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation/vandermonde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/internal"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
)

// ID uniquely identifies a shareholder.
type ID = internal.ID

// Threshold represents a (t,n) threshold access structure where
// any subset of at least t shareholders (out of n total) is authorized to
// reconstruct the secret.
type Threshold struct {
	t  uint
	ps ds.Set[ID]
}

// NewThresholdAccessStructure creates a new threshold access structure.
//
// Parameters:
//   - t: The threshold (minimum shares required), must be at least 2
//   - ps: The set of shareholder IDs, must not contain 0
//
// Returns an error if t < 2, t > |ps|, ps is nil, or ps contains 0.
func NewThresholdAccessStructure(t uint, ps ds.Set[ID]) (*Threshold, error) {
	if ps == nil {
		return nil, ErrIsNil.WithMessage("party set is nil")
	}
	if ps.Contains(0) {
		return nil, ErrMembership.WithMessage("party set cannot contain 0")
	}
	if t < 2 {
		return nil, ErrValue.WithMessage("threshold cannot be less than 2")
	}
	if t > uint(ps.Size()) {
		return nil, ErrValue.WithMessage("total cannot be less than threshold")
	}
	return &Threshold{
		t:  t,
		ps: ps,
	}, nil
}

// Threshold returns the minimum number of shares required for reconstruction.
func (a *Threshold) Threshold() uint {
	return a.t
}

// Shareholders returns the set of all valid shareholder IDs.
func (a *Threshold) Shareholders() ds.Set[ID] {
	return a.ps
}

// IsQualified returns true if the given set of shareholder IDs forms an
// authorized subset (i.e., has at least t members, all from the shareholder set).
func (a *Threshold) IsQualified(ids ...ID) bool {
	idsSet := hashset.NewComparable(ids...).Freeze()
	return idsSet.Size() >= int(a.t) &&
		idsSet.IsSubSet(a.ps)
}

// MaximalUnqualifiedSetsIter streams all size-(t-1) subsets of shareholders.
func (a *Threshold) MaximalUnqualifiedSetsIter() iter.Seq[ds.Set[ID]] {
	return func(yield func(ds.Set[ID]) bool) {
		for c := range sliceutils.Combinations(a.ps.List(), a.t-1) {
			s := hashset.NewComparable(c...)
			if cont := yield(s.Freeze()); !cont {
				break
			}
		}
	}
}

// Equal returns true if two access structures have the same threshold and shareholders.
func (a *Threshold) Equal(other *Threshold) bool {
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
func (a *Threshold) Clone() *Threshold {
	if a == nil {
		return nil
	}
	return &Threshold{
		t:  a.t,
		ps: a.ps.Clone(),
	}
}

// InducedMSP constructs an ideal monotone span programme from a
// threshold access structure using a Vandermonde matrix.
func InducedMSP[E algebra.PrimeFieldElement[E]](f algebra.PrimeField[E], ac *Threshold) (*msp.MSP[E], error) {
	if f == nil {
		return nil, ErrIsNil.WithMessage("base field cannot be nil")
	}
	if ac == nil {
		return nil, ErrIsNil.WithMessage("access structure cannot be nil")
	}

	shareHolders := ac.Shareholders().List()
	slices.Sort(shareHolders) // Ensure consistent ordering of shareholders

	// Build the n × t Vandermonde matrix where M[i,j] = α_i^j.
	// Each α_i is the field element corresponding to shareholder ID i.
	// Any t rows with distinct α_i form an invertible t×t Vandermonde,
	// so the target e₀ = (1,0,…,0) is in their row span.
	nodes := make([]E, len(shareHolders))
	for i, id := range shareHolders {
		nodes[i] = f.FromUint64(uint64(id))
	}
	matrix, err := vandermonde.BuildVandermondeMatrix(nodes, ac.Threshold())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to build Vandermonde matrix for threshold MSP")
	}

	rowsToHolders := make(map[int]ID)
	for i, id := range shareHolders {
		rowsToHolders[i] = id
	}
	out, err := msp.NewMSP(matrix, rowsToHolders)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create MSP from threshold access structure")
	}
	return out, nil
}
