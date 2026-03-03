package pedersen

import (
	"io"
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/errs-go/errs"
)

type Scheme[
	US sharing.LinearShare[US, USV], USV algebra.PrimeFieldElement[USV],
	W interface {
		sharing.Secret[W]
		base.Transparent[WV]
	}, WV algebra.GroupElement[WV],
	UDO sharing.DealerOutput[US],
	AC accessstructures.Monotone,
	ULDF sharing.LinearDealerFunc[ULDF, LFTUDF, US, USV, LFTUS, LFTUSV, AC],
	LFTUDF sharing.DealerFunc[LFTUDF, LFTUS, LFTUSV, AC],
	LFTUS sharing.LinearShare[LFTUS, LFTUSV],
	LFTUSV algebra.PrimeGroupElement[LFTUSV, USV],
] struct {
	key              *pedcom.Key[LFTUSV, USV]
	lsss             sharing.LSSS[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV]
	commitmentScheme *pedcom.Scheme[LFTUSV, USV]
}

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV]) Name() sharing.Name {
	return Name
}

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV]) AccessStructure() AC {
	return s.lsss.AccessStructure()
}

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV]) Deal(secret W, prng io.Reader) (*DealerOutput[LFTUDF, LFTUSV, LFTUS, USV, AC], error) {
	do, _, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to deal shares")
	}
	return do, nil
}

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV]) DealAndRevealDealerFunc(secret W, prng io.Reader) (
	*DealerOutput[LFTUDF, LFTUSV, LFTUS, USV, AC], *LinearDealerFunc[US, USV, LFTUS, LFTUSV, AC, ULDF, LFTUDF], error,
) {
	dealtShares, shareDealerFunc, err := s.lsss.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to deal secret")
	}
	liftedShareDealerFunc, err := shareDealerFunc.Lift(s.key.G())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to lift share dealer function")
	}
	blindingShares, _, blindingDealerFunc, err := s.lsss.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to deal blinding shares")
	}
	liftedBlindingDealerFunc, err := blindingDealerFunc.Lift(s.key.H())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to lift blinding dealer function")
	}
	verificationVector := liftedShareDealerFunc.Op(liftedBlindingDealerFunc)
	shares := hashmap.NewComparableFromNativeLike(
		maps.Collect(
			iterutils.Map2(
				dealtShares.Shares().Iter(),
				func(id sharing.ID, underlyingShare US) (sharing.ID, *Share[USV]) {
					blindingShare, _ := blindingShares.Shares().Get(id)
					messages := slices.Collect(iterutils.Map(
						underlyingShare.Repr(),
						func(shareComponent USV) *pedcom.Message[USV] {
							return pedcom.NewMessage(shareComponent)
						},
					))
					witnesses := slices.Collect(iterutils.Map(
						blindingShare.Repr(),
						func(blindingComponent USV) *pedcom.Witness[USV] {
							out, _ := pedcom.NewWitness(blindingComponent)
							return out
						},
					))
					share, _ := NewShare(id, messages, witnesses, nil)
					return id, share
				},
			),
		),
	)
	return &DealerOutput[LFTUDF, LFTUSV, LFTUS, USV, AC]{
			shares:             shares.Freeze(),
			verificationVector: verificationVector,
		}, &LinearDealerFunc[US, USV, LFTUS, LFTUSV, AC, ULDF, LFTUDF]{
			shares:   shareDealerFunc,
			blinding: blindingDealerFunc,
		}, nil
}

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV]) DealRandomAndRevealDealerFunc(prng io.Reader) (
	*DealerOutput[LFTUDF, LFTUSV, LFTUS, USV, AC], W, *LinearDealerFunc[US, USV, LFTUS, LFTUSV, AC, ULDF, LFTUDF], error,
) {
	dealtShares, dealtSecret, shareDealerFunc, err := s.lsss.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, *new(W), nil, errs.Wrap(err).WithMessage("failed to deal secret")
	}
	liftedShareDealerFunc, err := shareDealerFunc.Lift(s.key.G())
	if err != nil {
		return nil, *new(W), nil, errs.Wrap(err).WithMessage("failed to lift share dealer function")
	}
	blindingShares, _, blindingDealerFunc, err := s.lsss.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, *new(W), nil, errs.Wrap(err).WithMessage("failed to deal blinding shares")
	}
	liftedBlindingDealerFunc, err := blindingDealerFunc.Lift(s.key.H())
	if err != nil {
		return nil, *new(W), nil, errs.Wrap(err).WithMessage("failed to lift blinding dealer function")
	}
	verificationVector := liftedShareDealerFunc.Op(liftedBlindingDealerFunc)
	shares := hashmap.NewComparableFromNativeLike(
		maps.Collect(
			iterutils.Map2(
				dealtShares.Shares().Iter(),
				func(id sharing.ID, underlyingShare US) (sharing.ID, *Share[USV]) {
					blindingShare, _ := blindingShares.Shares().Get(id)
					messages := slices.Collect(iterutils.Map(
						underlyingShare.Repr(),
						func(shareComponent USV) *pedcom.Message[USV] {
							return pedcom.NewMessage(shareComponent)
						},
					))
					witnesses := slices.Collect(iterutils.Map(
						blindingShare.Repr(),
						func(blindingComponent USV) *pedcom.Witness[USV] {
							out, _ := pedcom.NewWitness(blindingComponent)
							return out
						},
					))
					share, _ := NewShare(id, messages, witnesses, nil)
					return id, share
				},
			),
		),
	)
	return &DealerOutput[LFTUDF, LFTUSV, LFTUS, USV, AC]{
			shares:             shares.Freeze(),
			verificationVector: verificationVector,
		}, dealtSecret, &LinearDealerFunc[US, USV, LFTUS, LFTUSV, AC, ULDF, LFTUDF]{
			shares:   shareDealerFunc,
			blinding: blindingDealerFunc,
		}, nil
}

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV]) DealRandom(prng io.Reader) (*DealerOutput[LFTUDF, LFTUSV, LFTUS, USV, AC], W, error) {
	do, secret, _, err := s.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, *new(W), errs.Wrap(err).WithMessage("failed to deal random secret")
	}
	return do, secret, nil
}

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV]) Reconstruct(shares ...*Share[USV]) (W, error) {
	underlyingShares := make([]US, len(shares))
	for i, share := range shares {
		underlyingShares[i] = share.secret
	}
	reconstructed, err := s.lsss.Reconstruct(underlyingShares...)
	if err != nil {
		return *new(W), errs.Wrap(err).WithMessage("failed to reconstruct secret")
	}
	return reconstructed, nil
}

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV]) ReconstructAndVerify(reference sharing.DealerFunc[LFTUS, LFTEREPR, AC], shares ...*Share[USV]) (W, error) {
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

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV]) Verify(share *Share[USV], verificationVector LFTUDF) error {
	if !verificationVector.Accepts(s.AccessStructure()) {
		return sharing.ErrVerification.WithMessage("verification vector does not accept the scheme's access structure")
	}
	liftedShare := verificationVector.ShareOf(share.ID())
	liftedShareRepr := slices.Collect(liftedShare.Repr())
	commitments := make([]*pedcom.Commitment[LFTUSV, USV], len(liftedShareRepr))
	for i, component := range liftedShareRepr {
		commitment, err := pedcom.NewCommitment(component)
		if err != nil {
			return errs.Wrap(err).WithMessage("failed to create commitment from lifted share component")
		}
		commitments[i] = commitment
	}
	verifier, err := s.commitmentScheme.Verifier()
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create verifier")
	}
	for i, commitment := range commitments {
		if err := verifier.Verify(commitment, share.Secret()[i], share.Blinding()[i]); err != nil {
			return errs.Wrap(err).WithMessage("share verification failed")
		}
	}
	return nil
}

// func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, EREPR, LFTEREPR, LFTUS]) ConvertShareToAdditive(input *Share[USV], unanimity *accessstructures.Unanimity) (*additive.Share[WV], error) {
// 	out, err := s.lsss.ConvertShareToAdditive(input, unanimity)
// 	if err != nil {
// 		return nil, errs.Wrap(err).WithMessage("failed to convert share to additive")
// 	}
// 	return out, nil
// }
