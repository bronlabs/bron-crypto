package kw

import (
	"io"
	"maps"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
)

// Scheme implements MSP-based secret sharing for an arbitrary linear access
// structure over a prime field. It holds the induced MSP and delegates
// qualification checks to the underlying access structure.
type Scheme[FE algebra.PrimeFieldElement[FE]] struct {
	msp *msp.MSP[FE]
	ac  accessstructures.Linear
}

// NewScheme constructs a KW sharing scheme by inducing an MSP from the given
// linear access structure over the prime field f.
func NewScheme[FE algebra.PrimeFieldElement[FE]](f algebra.PrimeField[FE], ac accessstructures.Linear) (*Scheme[FE], error) {
	m, err := accessstructures.InducedMSP(f, ac)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create MSP for access structure")
	}
	return &Scheme[FE]{
		msp: m,
		ac:  ac,
	}, nil
}

// Name returns the canonical name of this scheme.
func (*Scheme[FE]) Name() sharing.Name {
	return Name
}

// AccessStructure returns the linear access structure associated with this scheme.
func (s *Scheme[FE]) AccessStructure() accessstructures.Linear {
	return s.ac
}

// MSP returns the monotone span program induced by the scheme's access structure.
func (s *Scheme[FE]) MSP() *msp.MSP[FE] {
	return s.msp
}

// DealRandomAndRevealDealerFunc samples a uniformly random secret, deals shares
// for it, and returns the shares, the secret, and the dealer function (lambda
// column vector). This is the most general dealing entry point.
func (s *Scheme[FE]) DealRandomAndRevealDealerFunc(prng io.Reader) (*DealerOutput[FE], *Secret[FE], *DealerFunc[FE], error) {
	if prng == nil {
		return nil, nil, nil, sharing.ErrIsNil.WithMessage("prng cannot be nil")
	}
	value, err := s.msp.BaseField().Random(prng)
	if err != nil {
		return nil, nil, nil, errs.Wrap(err).WithMessage("failed to sample random secret value")
	}
	secret := NewSecret(value)
	shares, dealerFunc, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, nil, errs.Wrap(err).WithMessage("failed to deal shares for random secret")
	}
	return shares, secret, dealerFunc, nil
}

// DealRandom samples a uniformly random secret and deals shares for it.
func (s *Scheme[FE]) DealRandom(prng io.Reader) (*DealerOutput[FE], *Secret[FE], error) {
	shares, secret, _, err := s.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to deal random shares")
	}
	return shares, secret, nil
}

// DealAndRevealDealerFunc deals shares for the given secret and also returns
// the dealer function (the full lambda = M * r column vector). The random
// column r is sampled from prng with r[0] = secret.
func (s *Scheme[FE]) DealAndRevealDealerFunc(secret *Secret[FE], prng io.Reader) (*DealerOutput[FE], *DealerFunc[FE], error) {
	if secret == nil {
		return nil, nil, sharing.ErrIsNil.WithMessage("secret cannot be nil")
	}
	if prng == nil {
		return nil, nil, sharing.ErrIsNil.WithMessage("prng cannot be nil")
	}
	columnFactory, err := mat.NewMatrixModule(s.msp.D(), 1, s.msp.BaseField())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to create column vector factory")
	}

	randomColumn, err := columnFactory.Random(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to generate random column vector")
	}
	if err := randomColumn.SetAssign(0, 0, secret.Value()); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to set secret value in random column vector")
	}
	df, err := NewDealerFunc(randomColumn, s.msp)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to create dealer function from random column")
	}
	shares := hashmap.NewComparable[sharing.ID, *Share[FE]]()
	for id := range s.ac.Shareholders().Iter() {
		share, err := df.ShareOf(id)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("failed to get share for shareholder %d", id)
		}
		shares.Put(id, share)
	}

	return &DealerOutput[FE]{
		shares: shares.Freeze(),
	}, df, nil
}

// Deal distributes shares of the given secret to all shareholders.
func (s *Scheme[FE]) Deal(secret *Secret[FE], prng io.Reader) (*DealerOutput[FE], error) {
	out, _, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to deal shares")
	}
	return out, nil
}

// Reconstruct recovers the secret from a qualified set of shares. It computes
// the MSP reconstruction vector and takes its dot product with the assembled
// share column. Returns an error if the shares do not form a qualified set.
func (s *Scheme[FE]) Reconstruct(shares ...*Share[FE]) (*Secret[FE], error) {
	if len(shares) == 0 {
		return nil, sharing.ErrValue.WithMessage("no shares provided for reconstruction")
	}
	sharesSet := hashset.NewHashable(shares...)
	ids, err := sharing.CollectIDs(sharesSet.List()...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not collect IDs from shares")
	}
	if !s.ac.IsQualified(ids...) {
		return nil, sharing.ErrFailed.WithMessage("shares are not authorized by the access structure")
	}

	reconVec, err := s.msp.ReconstructionVector(ids...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute reconstruction vector for given shares")
	}
	shareCol, err := s.shareColumn(shares...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to assemble share column vector for reconstruction")
	}

	secret, err := reconVec.DotProduct(shareCol)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute reconstruction dot product")
	}
	return NewSecret(secret), nil
}

// shareColumn assembles the share values into a column vector ordered by
// ascending MSP row index, matching the ordering of ReconstructionVector.
func (s *Scheme[FE]) shareColumn(shares ...*Share[FE]) (*mat.Matrix[FE], error) {
	htr := s.msp.HoldersToRows()
	nRows := 0
	for _, sh := range shares {
		rowsi, exists := htr.Get(sh.id)
		if !exists {
			return nil, sharing.ErrMembership.WithMessage("shareholder %d is not in the MSP holders mapping", sh.id)
		}
		nRows += len(rowsi.List())
	}
	columnFactory, err := mat.NewMatrixModule(uint(nRows), 1, s.msp.BaseField())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create column vector factory")
	}

	// Assemble share values as a column vector in ascending row order,
	// matching the ordering used by ReconstructionVector.
	// share.v was stored in sorted row order during dealing, so we must
	// sort the row indices here to maintain the same correspondence.
	lambdaByRow := make(map[int]FE)
	for _, sh := range shares {
		rowsi, exists := htr.Get(sh.id)
		if !exists {
			return nil, sharing.ErrMembership.WithMessage("shareholder %d is not in the MSP holders mapping", sh.id)
		}
		sortedRows := slices.Sorted(slices.Values(rowsi.List()))
		for i, r := range sortedRows {
			lambdaByRow[r] = sh.v[i]
		}
	}
	shareCol := columnFactory.Zero()
	for i, r := range slices.Sorted(maps.Keys(lambdaByRow)) {
		if err := shareCol.SetAssign(i, 0, lambdaByRow[r]); err != nil {
			return nil, errs.Wrap(err).WithMessage("failed to build share column vector")
		}
	}
	return shareCol, nil
}

// ConvertShareToAdditive converts a KW share into an additive share under the
// given unanimity quorum. It computes the dot product of the shareholder's
// reconstruction-vector coefficients with their share components, producing a
// single field element. The sum of all such additive shares across the quorum
// recovers the original secret.
func (s *Scheme[FE]) ConvertShareToAdditive(share *Share[FE], quorum *unanimity.Unanimity) (*additive.Share[FE], error) {
	if share == nil {
		return nil, sharing.ErrIsNil.WithMessage("share cannot be nil")
	}
	if quorum == nil {
		return nil, sharing.ErrIsNil.WithMessage("quorum cannot be nil")
	}
	if !quorum.Shareholders().Contains(share.ID()) {
		return nil, sharing.ErrMembership.WithMessage("shareholder %d is not in the unanimity quorum", share.ID())
	}
	quorumIDs := quorum.Shareholders().List()
	if !s.ac.IsQualified(quorumIDs...) {
		return nil, sharing.ErrMembership.WithMessage("quorum shareholders are not qualified by the access structure")
	}

	reconVec, err := s.msp.ReconstructionVector(quorumIDs...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute reconstruction vector for unanimity quorum")
	}
	shareCol, err := s.shareColumn(share)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to assemble share column vector for conversion")
	}

	// reconVec is indexed 0..len(allQuorumRows)-1, with entries ordered by
	// ascending absolute MSP row index across all quorum members. Map this
	// shareholder's absolute row indices to their positions in reconVec.
	htr := s.msp.HoldersToRows()
	var allQuorumRows []int
	for _, id := range quorumIDs {
		rows, ok := htr.Get(id)
		if !ok {
			return nil, sharing.ErrMembership.WithMessage("quorum shareholder %d is not in the MSP holders mapping", id)
		}
		allQuorumRows = append(allQuorumRows, rows.List()...)
	}
	slices.Sort(allQuorumRows)

	shareholderAbsRowsSet, ok := htr.Get(share.ID())
	if !ok {
		return nil, sharing.ErrMembership.WithMessage("shareholder %d is not in the MSP holders mapping", share.ID())
	}
	shareholderAbsRows := shareholderAbsRowsSet.List()
	slices.Sort(shareholderAbsRows)
	reconPositions := make([]int, len(shareholderAbsRows))

	// Say the full MSP has 10 rows, quorum is {1, 3}, and:
	// - Shareholder 1 owns absolute rows [3, 6]
	// - Shareholder 3 owns absolute rows [0, 8]
	// Then:
	//   allQuorumRows = [0, 3, 6, 8]   (sorted)
	//   reconVec      has 4 entries, indexed 0..3
	//     reconVec[0] = coeff for abs row 0
	//     reconVec[1] = coeff for abs row 3
	//     reconVec[2] = coeff for abs row 6
	//     reconVec[3] = coeff for abs row 8
	//   For shareholder 1 with shareholderAbsRows = [3, 6]:
	//   BinarySearch([0,3,6,8], 3) → pos=1
	//   BinarySearch([0,3,6,8], 6) → pos=2
	//   reconPositions = [1, 2]
	// BinarySearch returns the position of the value within allQuorumRows,
	for i, absRow := range shareholderAbsRows {
		pos, found := slices.BinarySearch(allQuorumRows, absRow)
		if !found {
			return nil, sharing.ErrFailed.WithMessage("shareholder row %d not found in quorum rows", absRow)
		}
		reconPositions[i] = pos
	}

	reconSubVec, err := reconVec.SubMatrixGivenRows(reconPositions...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to extract reconstruction vector coefficients for share's rows")
	}

	// shareCol already contains exactly this shareholder's values in ascending
	// row order, so the dot product pairs entries correctly.
	additiveShareValue, err := reconSubVec.DotProduct(shareCol)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute additive share value as dot product")
	}

	additiveShare, err := additive.NewShare(share.ID(), additiveShareValue, quorum)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create additive share from converted value")
	}
	return additiveShare, nil
}
