package feldman

import (
	"io"
	"maps"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/errs-go/errs"
)

type Scheme[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	group algebra.PrimeGroup[E, FE]
	lsss  *kw.Scheme[FE]
}

func NewScheme[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](group algebra.PrimeGroup[E, FE], accessStructure accessstructures.Linear) (*Scheme[E, FE], error) {
	if group == nil {
		return nil, sharing.ErrIsNil.WithMessage("group is nil")
	}
	if accessStructure == nil {
		return nil, sharing.ErrIsNil.WithMessage("access structure is nil")
	}

	field := algebra.StructureMustBeAs[algebra.PrimeField[FE]](group.ScalarStructure())

	lsss, err := kw.NewScheme(field, accessStructure)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create LSSS scheme")
	}
	return &Scheme[E, FE]{
		group: group,
		lsss:  lsss,
	}, nil
}

func (*Scheme[E, FE]) Name() sharing.Name {
	return Name
}

func (s *Scheme[E, FE]) AccessStructure() accessstructures.Linear {
	return s.lsss.AccessStructure()
}

func (s *Scheme[E, FE]) DealRandom(prng io.Reader) (*DealerOutput[E, FE], *kw.Secret[FE], error) {
	do, secret, _, err := s.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to deal shares")
	}
	return do, secret, nil
}

func (s *Scheme[E, FE]) DealRandomAndRevealDealerFunc(prng io.Reader) (*DealerOutput[E, FE], *kw.Secret[FE], *DealerFunc[FE], error) {
	lsssOutput, secret, matrix, err := s.lsss.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, nil, errs.Wrap(err).WithMessage("failed to deal shares")
	}

	verificationMatrix, err := mat.LiftMatrix(matrix, s.group.Generator())
	if err != nil {
		return nil, nil, nil, errs.Wrap(err).WithMessage("failed to lift matrix for verification commitments")
	}
	shares := hashmap.NewComparableFromNativeLike(maps.Collect(lsssOutput.Shares().Iter())).Freeze()

	return &DealerOutput[E, FE]{
		shares: shares,
		v:      verificationMatrix,
	}, secret, matrix, nil
}

func (s *Scheme[E, FE]) Deal(secret *kw.Secret[FE], prng io.Reader) (*DealerOutput[E, FE], error) {
	do, _, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to deal shares")
	}
	return do, nil
}

func (s *Scheme[E, FE]) DealAndRevealDealerFunc(secret *kw.Secret[FE], prng io.Reader) (*DealerOutput[E, FE], *DealerFunc[FE], error) {
	lsssOutput, matrix, err := s.lsss.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to deal shares")
	}

	verificationMatrix, err := mat.LiftMatrix(matrix, s.group.Generator())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to lift matrix for verification commitments")
	}
	shares := hashmap.NewComparableFromNativeLike(maps.Collect(lsssOutput.Shares().Iter())).Freeze()

	return &DealerOutput[E, FE]{
		shares: shares,
		v:      verificationMatrix,
	}, matrix, nil
}

func (s *Scheme[E, FE]) Reconstruct(shares ...*kw.Share[FE]) (*kw.Secret[FE], error) {
	out, err := s.lsss.Reconstruct(shares...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to reconstruct secret")
	}
	return out, nil
}

// func (s *Scheme[E, FE]) Verify(share *kw.Share[FE], reference *VerificationMatrix[E, FE]) error {
