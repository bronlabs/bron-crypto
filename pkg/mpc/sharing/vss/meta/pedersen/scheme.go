package pedersen

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/errs-go/errs"
)

type Scheme[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	commitmentScheme *pedcom.Scheme[E, S]
	lsss             *kw.Scheme[S]
}

func (s *Scheme[E, S]) Name() sharing.Name {
	return Name
}

func (s *Scheme[E, S]) AccessStructure() accessstructures.Linear {
	return s.lsss.AccessStructure()
}

func (s *Scheme[E, S]) Deal(secret *kw.Secret[S], prng io.Reader) (*DealerOutput[E, S], error) {
	do, _, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not deal and reveal dealer func")
	}
	return do, nil
}

func (s *Scheme[E, S]) DealAndRevealDealerFunc(secret *kw.Secret[S], prng io.Reader) (*DealerOutput[E, S], *DealerFunc[S], error) {
	if secret == nil {
		return nil, nil, sharing.ErrIsNil.WithMessage("secret is nil")
	}
	if prng == nil {
		return nil, nil, sharing.ErrIsNil.WithMessage("prng is nil")
	}

	secretShares, secretsDealerFunc, err := s.lsss.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not deal and reveal dealer func using LSSS scheme")
	}
	blindingShares, _, blindingDealerFunc, err := s.lsss.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not deal and reveal dealer func for blinding using LSSS scheme")
	}

	dealerFunc, err := NewDealerFunc(secretsDealerFunc, blindingDealerFunc)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create Pedersen dealer func")
	}
	liftedDealerFunc, err := LiftDealerFunc(dealerFunc, s.commitmentScheme.Key())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not lift Pedersen dealer func")
	}

	shares := hashmap.NewComparable[sharing.ID, *Share[S]]()
	for id, secretShare := range secretShares.Shares().Iter() {
		blindingShare, exists := blindingShares.Shares().Get(id)
		if !exists {
			return nil, nil, sharing.ErrFailed.WithMessage("missing blinding share for ID %d", id)
		}

		share, err := NewShare(id, secretShare, blindingShare, s.lsss.AccessStructure())
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("could not create Pedersen share")
		}

		shares.Put(id, share)
	}
	return &DealerOutput[E, S]{
		shares: shares.Freeze(),
		v:      liftedDealerFunc.VerificationVector(),
	}, dealerFunc, nil
}

func (s *Scheme[E, S]) DealRandom(prng io.Reader) (*DealerOutput[E, S], *kw.Secret[S], error) {
	do, secret, _, err := s.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not deal random shares and reveal dealer func")
	}
	return do, secret, nil
}

func (s *Scheme[E, S]) DealRandomAndRevealDealerFunc(prng io.Reader) (*DealerOutput[E, S], *kw.Secret[S], *DealerFunc[S], error) {
	if prng == nil {
		return nil, nil, nil, sharing.ErrIsNil.WithMessage("prng is nil")
	}
	secretValue, err := s.lsss.MSP().BaseField().Random(prng)
	if err != nil {
		return nil, nil, nil, errs.Wrap(err).WithMessage("could not sample random secret value from LSSS scheme's MSP base field")
	}
	secret := kw.NewSecret(secretValue)
	do, df, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, nil, errs.Wrap(err).WithMessage("could not deal random shares and reveal dealer func")
	}
	return do, secret, df, nil
}

func (s *Scheme[E, S]) Reconstruct(shares ...*Share[S]) (*kw.Secret[S], error) {
	secretShares := make([]*kw.Share[S], len(shares))
	var err error
	for i, share := range shares {
		secretShares[i], err = kw.NewShare(share.ID(), sliceutils.Map(share.secret, func(m *pedcom.Message[S]) S { return m.Value() })...)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not create Shamir share from Pedersen share: %v", err)
		}
	}
	secret, err := s.lsss.Reconstruct(secretShares...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not reconstruct secret using LSSS scheme: %v", err)
	}
	return secret, nil
}

func (s *Scheme[E, S]) ReconstructAndVerify(reference *VerificationVector[E, S], shares ...*Share[S]) (*kw.Secret[S], error) {
	reconstructed, err := s.Reconstruct(shares...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not reconstruct secret without verification")
	}
	for i, share := range shares {
		if err := s.Verify(share, reference); err != nil {
			return nil, errs.Wrap(err).WithMessage("verification failed for share %d", i)
		}
	}
	return reconstructed, nil
}

func (s *Scheme[E, S]) Verify(share *Share[S], vector *VerificationVector[E, S]) error {
	if share == nil {
		return sharing.ErrIsNil.WithMessage("share is nil")
	}
	if vector == nil {
		return sharing.ErrIsNil.WithMessage("verification vector is nil")
	}
	liftedDealerFunc, err := NewLiftedDealerFunc(vector, s.lsss.MSP())
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create lifted dealer func")
	}

	liftedShare, err := liftedDealerFunc.ShareOf(share.ID())
	if err != nil {
		return errs.Wrap(err).WithMessage("could not get lifted share for share ID %d", share.ID())
	}

	manuallyLiftedShare, err := LiftShare(share, s.commitmentScheme.Key())
	if err != nil {
		return errs.Wrap(err).WithMessage("could not manually lift share for share ID %d", share.ID())
	}

	if !liftedShare.Equal(manuallyLiftedShare) {
		return sharing.ErrVerification.WithMessage("verification failed for share ID %d", share.ID())
	}
	return nil
}

func (s *Scheme[E, S]) ConvertShareToAdditive(share *Share[S], quorum *unanimity.Unanimity) (*additive.Share[S], error) {
	kwShare, err := kw.NewShare(share.ID(), sliceutils.Map(share.secret, func(m *pedcom.Message[S]) S { return m.Value() })...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create Shamir share from Pedersen share")
	}
	out, err := s.lsss.ConvertShareToAdditive(kwShare, quorum)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not convert share to additive share using LSSS scheme")
	}
	return out, nil
}
