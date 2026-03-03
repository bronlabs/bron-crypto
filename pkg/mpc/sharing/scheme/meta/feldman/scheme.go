package feldman

import (
	"io"
	"maps"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/errs-go/errs"
)

type Scheme[
	S sharing.LinearShare[S, SV], SV any,
	W interface {
		sharing.Secret[W]
		base.Transparent[WV]
	}, WV algebra.GroupElement[WV],
	DO sharing.DealerOutput[S],
	AC accessstructures.Monotone,
	DF sharing.LinearDealerFunc[S, EREPR, LFTS, LFTEREPR, AC], EREPR any, LFTEREPR base.Equatable[LFTEREPR],
	LFTS sharing.LinearShare[LFTS, LFTEREPR],
] struct {
	basePoint LFTEREPR
	lsss      sharing.LSSS[S, SV, W, WV, DO, AC, DF, EREPR, LFTEREPR, LFTS]
	liftShare func(share SV, basePoint LFTEREPR) (LFTEREPR, error) // will lift to basepoint
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, EREPR, LFTEREPR, LFTS]) Name() sharing.Name {
	return Name
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, EREPR, LFTEREPR, LFTS]) AccessStructure() AC {
	return s.lsss.AccessStructure()
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, EREPR, LFTEREPR, LFTS]) Deal(secret W, prng io.Reader) (*DealerOutput[S, SV, LFTS, LFTEREPR, AC], error) {
	do, _, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to deal shares")
	}
	return do, nil
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, EREPR, LFTEREPR, LFTS]) DealAndRevealDealerFunc(secret W, prng io.Reader) (*DealerOutput[S, SV, LFTS, LFTEREPR, AC], DF, error) {
	underlyingShares, underlyingDealerFunc, err := s.lsss.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, *new(DF), errs.Wrap(err).WithMessage("failed to deal secret")
	}
	liftedDealerFunc, err := underlyingDealerFunc.Lift(s.basePoint)
	if err != nil {
		return nil, *new(DF), errs.Wrap(err).WithMessage("failed to lift dealer function")
	}
	shares := hashmap.NewComparableFromNativeLike(maps.Collect(underlyingShares.Shares().Iter())).Freeze()
	return &DealerOutput[S, SV, LFTS, LFTEREPR, AC]{
		liftedDealerFunc: liftedDealerFunc,
		shares:           shares,
	}, underlyingDealerFunc, nil
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, EREPR, LFTEREPR, LFTS]) DealRandomAndRevealDealerFunc(prng io.Reader) (*DealerOutput[S, SV, LFTS, LFTEREPR, AC], W, DF, error) {
	underlyingShares, secret, underlyingDealerFunc, err := s.lsss.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, *new(W), *new(DF), errs.Wrap(err).WithMessage("failed to deal random secret")
	}
	liftedDealerFunc, err := underlyingDealerFunc.Lift(s.basePoint)
	if err != nil {
		return nil, *new(W), *new(DF), errs.Wrap(err).WithMessage("failed to lift dealer function")
	}
	shares := hashmap.NewComparableFromNativeLike(maps.Collect(underlyingShares.Shares().Iter())).Freeze()
	return &DealerOutput[S, SV, LFTS, LFTEREPR, AC]{
		liftedDealerFunc: liftedDealerFunc,
		shares:           shares,
	}, secret, underlyingDealerFunc, nil
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, EREPR, LFTEREPR, LFTS]) DealRandom(prng io.Reader) (*DealerOutput[S, SV, LFTS, LFTEREPR, AC], W, error) {
	do, secret, _, err := s.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, *new(W), errs.Wrap(err).WithMessage("failed to deal random secret")
	}
	return do, secret, nil
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, EREPR, LFTEREPR, LFTS]) Reconstruct(shares ...S) (W, error) {
	reconstructed, err := s.lsss.Reconstruct(shares...)
	if err != nil {
		return *new(W), errs.Wrap(err).WithMessage("failed to reconstruct secret")
	}
	return reconstructed, nil
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, EREPR, LFTEREPR, LFTS]) ReconstructAndVerify(reference sharing.DealerFunc[LFTS, LFTEREPR, AC], shares ...S) (W, error) {
	if reference == nil {
		return *new(W), sharing.ErrIsNil.WithMessage("reference dealer function is nil")
	}
	reconstructed, err := s.Reconstruct(shares...)
	if err != nil {
		return *new(W), errs.Wrap(err).WithMessage("failed to reconstruct secret")
	}
	for _, share := range shares {
		if err := s.Verify(share, reference); err != nil {
			return *new(W), errs.Wrap(err).WithMessage("share verification failed during reconstruction")
		}
	}
	return reconstructed, nil
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, EREPR, LFTEREPR, LFTS]) Verify(share S, liftedDealerFunc sharing.DealerFunc[LFTS, LFTEREPR, AC]) error {
	if liftedDealerFunc == nil {
		return sharing.ErrIsNil.WithMessage("lifted dealer function is nil")
	}
	if !liftedDealerFunc.Accepts(s.lsss.AccessStructure()) {
		return sharing.ErrVerification.WithMessage("lifted dealer function does not accept scheme's access structure")
	}
	liftedShare := liftedDealerFunc.ShareOf(share.ID())
	manuallyLiftedShareValue, err := s.liftShare(share.Value(), s.basePoint)
	if err != nil {
		return err
	}
	if !liftedShare.Value().Equal(manuallyLiftedShareValue) {
		return sharing.ErrVerification.WithMessage("share verification failed")
	}
	return nil
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, EREPR, LFTEREPR, LFTS]) ConvertShareToAdditive(input S, unanimity *accessstructures.Unanimity) (*additive.Share[WV], error) {
	out, err := s.lsss.ConvertShareToAdditive(input, unanimity)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to convert share to additive")
	}
	return out, nil
}
