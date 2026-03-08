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
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/msp"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
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
	lambda, err := s.msp.Matrix().TryMul(randomColumn)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to compute lambda = M * r")
	}

	shares := hashmap.NewComparable[sharing.ID, *Share[FE]]()
	for id := range s.ac.Shareholders().Iter() {
		lambdaI, err := lambda.SubMatrixGivenRows(s.msp.HoldersToRows()[id]...)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("failed to extract lambda_i for shareholder %d", id)
		}
		shares.Put(
			id,
			&Share[FE]{
				id: id,
				v:  slices.Collect(lambdaI.Iter()),
			},
		)
	}

	return &DealerOutput[FE]{
		shares: shares.Freeze(),
	}, lambda, nil
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
		nRows += len(htr[sh.id])
	}
	columnFactory, err := mat.NewMatrixModule(uint(nRows), 1, s.msp.BaseField())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create column vector factory")
	}

	// Assemble share values as a column vector in ascending row order,
	// matching the ordering used by ReconstructionVector.
	lambdaByRow := make(map[int]FE)
	for _, sh := range shares {
		for i, r := range htr[sh.id] {
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
// given unanimity quorum. Not yet implemented.
func (*Scheme[FE]) ConvertShareToAdditive(s *Share[FE], quorum *unanimity.Unanimity) (*additive.Share[FE], error) {
	panic("not implemented")
}
