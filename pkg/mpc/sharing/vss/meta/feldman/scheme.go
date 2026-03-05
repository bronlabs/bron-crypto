package feldman

import (
	"io"
	"maps"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
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
	}, WV algebra.RingElement[WV],
	DO sharing.DealerOutput[S],
	AC accessstructures.Monotone,
	DF sharing.DealerFunc[S, SV, AC],
	LFTDF interface {
		algebra.Operand[LFTDF]
		sharing.DealerFunc[LFTS, LFTSV, AC]
	}, LFTS sharing.LinearShare[LFTS, LFTSV],
	LFTSV algebra.ModuleElement[LFTSV, SV],
	LFTW interface {
		sharing.Secret[LFTW]
		base.Transparent[LFTWV]
	}, LFTWV algebra.ModuleElement[LFTWV, WV],
](
	basePoint LFTSV,
	lsss sharing.LiftableLSSS[S, SV, W, WV, DO, AC, DF, LFTS, LFTSV, LFTDF, LFTW, LFTWV],
) (*Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV], error) {
	if lsss == nil {
		return nil, sharing.ErrIsNil.WithMessage("liftable LSSS cannot be nil")
	}
	if utils.IsNil(basePoint) {
		return nil, sharing.ErrIsNil.WithMessage("base point cannot be nil")
	}
	return &Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]{
		basePoint: basePoint,
		lsss:      lsss,
	}, nil
}

type Scheme[
	S sharing.LinearShare[S, SV], SV algebra.RingElement[SV],
	W interface {
		sharing.Secret[W]
		base.Transparent[WV]
	}, WV algebra.RingElement[WV],
	DO sharing.DealerOutput[S],
	AC accessstructures.Monotone,
	DF sharing.DealerFunc[S, SV, AC],
	LFTDF interface {
		algebra.Operand[LFTDF]
		sharing.DealerFunc[LFTS, LFTSV, AC]
	}, LFTS sharing.LinearShare[LFTS, LFTSV],
	LFTSV algebra.ModuleElement[LFTSV, SV],
	LFTW interface {
		sharing.Secret[LFTW]
		base.Transparent[LFTWV]
	}, LFTWV algebra.ModuleElement[LFTWV, WV],
] struct {
	basePoint LFTSV
	lsss      sharing.LiftableLSSS[S, SV, W, WV, DO, AC, DF, LFTS, LFTSV, LFTDF, LFTW, LFTWV]
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]) Name() sharing.Name {
	return Name
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]) AccessStructure() AC {
	return s.lsss.AccessStructure()
}

// TODO: enforce by interface
func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]) UnderlyingLSSS() sharing.LiftableLSSS[S, SV, W, WV, DO, AC, DF, LFTS, LFTSV, LFTDF, LFTW, LFTWV] {
	return s.lsss
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]) Deal(secret W, prng io.Reader) (*DealerOutput[S, SV, LFTDF, LFTS, LFTSV, AC], error) {
	do, _, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to deal shares")
	}
	return do, nil
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]) DealAndRevealDealerFunc(secret W, prng io.Reader) (*DealerOutput[S, SV, LFTDF, LFTS, LFTSV, AC], DF, error) {
	underlyingShares, underlyingDealerFunc, err := s.lsss.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, *new(DF), errs.Wrap(err).WithMessage("failed to deal secret")
	}
	liftedDealerFunc, err := s.lsss.LiftDealerFunc(underlyingDealerFunc, s.basePoint)
	if err != nil {
		return nil, *new(DF), errs.Wrap(err).WithMessage("failed to lift dealer function")
	}
	shares := hashmap.NewComparableFromNativeLike(maps.Collect(underlyingShares.Shares().Iter())).Freeze()
	return &DealerOutput[S, SV, LFTDF, LFTS, LFTSV, AC]{

		verificationVector: liftedDealerFunc,
		shares:             shares,
	}, underlyingDealerFunc, nil
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]) DealRandomAndRevealDealerFunc(prng io.Reader) (*DealerOutput[S, SV, LFTDF, LFTS, LFTSV, AC], W, DF, error) {
	underlyingShares, secret, underlyingDealerFunc, err := s.lsss.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, *new(W), *new(DF), errs.Wrap(err).WithMessage("failed to deal random secret")
	}
	liftedDealerFunc, err := s.lsss.LiftDealerFunc(underlyingDealerFunc, s.basePoint)
	if err != nil {
		return nil, *new(W), *new(DF), errs.Wrap(err).WithMessage("failed to lift dealer function")
	}
	shares := hashmap.NewComparableFromNativeLike(maps.Collect(underlyingShares.Shares().Iter())).Freeze()
	return &DealerOutput[S, SV, LFTDF, LFTS, LFTSV, AC]{
		verificationVector: liftedDealerFunc,
		shares:             shares,
	}, secret, underlyingDealerFunc, nil
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]) DealRandom(prng io.Reader) (*DealerOutput[S, SV, LFTDF, LFTS, LFTSV, AC], W, error) {
	do, secret, _, err := s.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, *new(W), errs.Wrap(err).WithMessage("failed to deal random secret")
	}
	return do, secret, nil
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]) Reconstruct(shares ...S) (W, error) {
	reconstructed, err := s.lsss.Reconstruct(shares...)
	if err != nil {
		return *new(W), errs.Wrap(err).WithMessage("failed to reconstruct secret")
	}
	return reconstructed, nil
}

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]) ReconstructAndVerify(reference LFTDF, shares ...S) (W, error) {
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

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]) Verify(share S, liftedDealerFunc LFTDF) error {
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

func (s *Scheme[S, SV, W, WV, DO, AC, DF, LFTDF, LFTS, LFTSV, LFTW, LFTWV]) ConvertShareToAdditive(input S, unanimity *accessstructures.Unanimity) (*additive.Share[WV], error) {
	out, err := s.lsss.ConvertShareToAdditive(input, unanimity)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to convert share to additive")
	}
	return out, nil
}
