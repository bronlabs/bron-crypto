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

func NewScheme[
	S sharing.LinearShare[S, SV], SV algebra.RingElement[SV],
	W interface {
		sharing.Secret[W]
		base.Transparent[WV]
	}, WV algebra.GroupElement[WV],
	DO sharing.DealerOutput[S],
	AC accessstructures.Monotone,
	DF sharing.DealerFunc[S, SV, AC],
	LFTDF interface {
		algebra.Operand[LFTDF]
		sharing.DealerFunc[LFTS, LFTSV, AC]
	}, LFTS sharing.LinearShare[LFTS, LFTSV],
	LFTSV algebra.ModuleElement[LFTSV, SV],
](
	basePoint LFTSV,
	lsss sharing.LiftableLSSS[S, SV, W, WV, DO, AC, DF, LFTS, LFTSV, LFTDF],
) *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV] {
	return &Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV]{
		basePoint: basePoint,
		lsss:      lsss,
	}
}

type Scheme[
	S sharing.LinearShare[S, SV], SV algebra.RingElement[SV],
	W interface {
		sharing.Secret[W]
		base.Transparent[WV]
	}, WV algebra.GroupElement[WV],
	DO sharing.DealerOutput[S],
	AC accessstructures.Monotone,
	DF sharing.DealerFunc[S, SV, AC],
	LFTDF interface {
		algebra.Operand[LFTDF]
		sharing.DealerFunc[LFTS, LFTSV, AC]
	}, LFTS sharing.LinearShare[LFTS, LFTSV],
	LFTSV algebra.ModuleElement[LFTSV, SV],
] struct {
	basePoint LFTSV
	lsss      sharing.LiftableLSSS[S, SV, W, WV, DO, AC, DF, LFTS, LFTSV, LFTDF]
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV]) Name() sharing.Name {
	return Name
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV]) AccessStructure() AC {
	return s.lsss.AccessStructure()
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV]) Deal(secret W, prng io.Reader) (*DealerOutput[S, LFTDF], error) {
	do, _, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to deal shares")
	}
	return do, nil
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV]) DealAndRevealDealerFunc(secret W, prng io.Reader) (*DealerOutput[S, LFTDF], DF, error) {
	underlyingShares, underlyingDealerFunc, err := s.lsss.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, *new(DF), errs.Wrap(err).WithMessage("failed to deal secret")
	}
	liftedDealerFunc, err := s.lsss.LiftDealerFunc(underlyingDealerFunc, s.basePoint)
	if err != nil {
		return nil, *new(DF), errs.Wrap(err).WithMessage("failed to lift dealer function")
	}
	shares := hashmap.NewComparableFromNativeLike(maps.Collect(underlyingShares.Shares().Iter())).Freeze()
	return &DealerOutput[S, LFTDF]{
		liftedDealerFunc: liftedDealerFunc,
		shares:           shares,
	}, underlyingDealerFunc, nil
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV]) DealRandomAndRevealDealerFunc(prng io.Reader) (*DealerOutput[S, LFTDF], W, DF, error) {
	underlyingShares, secret, underlyingDealerFunc, err := s.lsss.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, *new(W), *new(DF), errs.Wrap(err).WithMessage("failed to deal random secret")
	}
	liftedDealerFunc, err := s.lsss.LiftDealerFunc(underlyingDealerFunc, s.basePoint)
	if err != nil {
		return nil, *new(W), *new(DF), errs.Wrap(err).WithMessage("failed to lift dealer function")
	}
	shares := hashmap.NewComparableFromNativeLike(maps.Collect(underlyingShares.Shares().Iter())).Freeze()
	return &DealerOutput[S, LFTDF]{
		liftedDealerFunc: liftedDealerFunc,
		shares:           shares,
	}, secret, underlyingDealerFunc, nil
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV]) DealRandom(prng io.Reader) (*DealerOutput[S, LFTDF], W, error) {
	do, secret, _, err := s.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, *new(W), errs.Wrap(err).WithMessage("failed to deal random secret")
	}
	return do, secret, nil
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV]) Reconstruct(shares ...S) (W, error) {
	reconstructed, err := s.lsss.Reconstruct(shares...)
	if err != nil {
		return *new(W), errs.Wrap(err).WithMessage("failed to reconstruct secret")
	}
	return reconstructed, nil
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV]) ReconstructAndVerify(reference LFTDF, shares ...S) (W, error) {
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

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV]) Verify(share S, liftedDealerFunc LFTDF) error {
	if !liftedDealerFunc.Accepts(s.lsss.AccessStructure()) {
		return sharing.ErrVerification.WithMessage("lifted dealer function does not accept scheme's access structure")
	}
	liftedShare := liftedDealerFunc.ShareOf(share.ID())

	manuallyLiftedShare, err := s.lsss.LiftShare(share, s.basePoint)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to lift share for verification")
	}
	if !liftedShare.Equal(manuallyLiftedShare) {
		return sharing.ErrVerification.WithMessage("share verification failed")
	}
	return nil
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV]) ConvertShareToAdditive(input S, unanimity *accessstructures.Unanimity) (*additive.Share[WV], error) {
	out, err := s.lsss.ConvertShareToAdditive(input, unanimity)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to convert share to additive")
	}
	return out, nil
}
