package pedersen

import (
	"io"
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/errs-go/errs"
)

func NewScheme[
	US sharing.LinearShare[US, USV], USV algebra.PrimeFieldElement[USV],
	W interface {
		sharing.Secret[W]
		base.Transparent[WV]
	}, WV algebra.RingElement[WV],
	UDO sharing.DealerOutput[US],
	AC accessstructures.Monotone,
	ULDF sharing.DealerFunc[US, USV, AC],
	LFTUDF interface {
		algebra.Operand[LFTUDF]
		sharing.DealerFunc[LFTUS, LFTUSV, AC]
	}, LFTUS sharing.LinearShare[LFTUS, LFTUSV],
	LFTUSV algebra.PrimeGroupElement[LFTUSV, USV],
	LFTW interface {
		sharing.Secret[LFTW]
		base.Transparent[LFTWV]
	}, LFTWV algebra.ModuleElement[LFTWV, WV],
](
	key *pedcom.Key[LFTUSV, USV],
	lsss sharing.LiftableLSSS[US, USV, W, WV, UDO, AC, ULDF, LFTUS, LFTUSV, LFTUDF, LFTW, LFTWV],
) (*Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV, LFTW, LFTWV], error) {
	if key == nil {
		return nil, sharing.ErrIsNil.WithMessage("key cannot be nil")
	}
	if lsss == nil {
		return nil, sharing.ErrIsNil.WithMessage("liftable LSSS cannot be nil")
	}
	commitmentScheme, err := pedcom.NewScheme(key)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create commitment scheme")
	}
	return &Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV, LFTW, LFTWV]{
		key:              key,
		lsss:             lsss,
		commitmentScheme: commitmentScheme,
	}, nil
}

type Scheme[
	US sharing.LinearShare[US, USV], USV algebra.PrimeFieldElement[USV],
	W interface {
		sharing.Secret[W]
		base.Transparent[WV]
	}, WV algebra.RingElement[WV],
	UDO sharing.DealerOutput[US],
	AC accessstructures.Monotone,
	ULDF sharing.DealerFunc[US, USV, AC],
	LFTUDF interface {
		algebra.Operand[LFTUDF]
		sharing.DealerFunc[LFTUS, LFTUSV, AC]
	}, LFTUS sharing.LinearShare[LFTUS, LFTUSV],
	LFTUSV algebra.PrimeGroupElement[LFTUSV, USV],
	LFTW interface {
		sharing.Secret[LFTW]
		base.Transparent[LFTWV]
	}, LFTWV algebra.ModuleElement[LFTWV, WV],
] struct {
	key              *pedcom.Key[LFTUSV, USV]
	lsss             sharing.LiftableLSSS[US, USV, W, WV, UDO, AC, ULDF, LFTUS, LFTUSV, LFTUDF, LFTW, LFTWV]
	commitmentScheme *pedcom.Scheme[LFTUSV, USV]
}

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV, LFTW, LFTWV]) Name() sharing.Name {
	return Name
}

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV, LFTW, LFTWV]) AccessStructure() AC {
	return s.lsss.AccessStructure()
}

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV, LFTW, LFTWV]) UnderlyingLSSS() sharing.LiftableLSSS[US, USV, W, WV, UDO, AC, ULDF, LFTUS, LFTUSV, LFTUDF, LFTW, LFTWV] {
	return s.lsss
}

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV, LFTW, LFTWV]) Deal(secret W, prng io.Reader) (*DealerOutput[US, USV, LFTUDF, LFTUS, LFTUSV, AC], error) {
	do, _, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to deal shares")
	}
	return do, nil
}

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV, LFTW, LFTWV]) DealAndRevealDealerFunc(secret W, prng io.Reader) (
	*DealerOutput[US, USV, LFTUDF, LFTUS, LFTUSV, AC], *DealerFunc[ULDF, US, USV, AC], error,
) {
	dealtShares, shareDealerFunc, err := s.lsss.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to deal secret")
	}
	return s.dealBlindingAndFinalise(dealtShares, shareDealerFunc, prng)
}

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV, LFTW, LFTWV]) DealRandomAndRevealDealerFunc(prng io.Reader) (
	*DealerOutput[US, USV, LFTUDF, LFTUS, LFTUSV, AC], W, *DealerFunc[ULDF, US, USV, AC], error,
) {
	dealtShares, dealtSecret, shareDealerFunc, err := s.lsss.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, *new(W), nil, errs.Wrap(err).WithMessage("failed to deal secret")
	}
	do, ldf, err := s.dealBlindingAndFinalise(dealtShares, shareDealerFunc, prng)
	if err != nil {
		return nil, *new(W), nil, err
	}
	return do, dealtSecret, ldf, nil
}

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV, LFTW, LFTWV]) dealBlindingAndFinalise(
	dealtShares UDO, shareDealerFunc ULDF, prng io.Reader,
) (*DealerOutput[US, USV, LFTUDF, LFTUS, LFTUSV, AC], *DealerFunc[ULDF, US, USV, AC], error) {
	liftedShareDealerFunc, err := s.lsss.LiftDealerFunc(shareDealerFunc, s.key.G())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to lift share dealer function")
	}
	blindingShares, _, blindingDealerFunc, err := s.lsss.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to deal blinding shares")
	}
	liftedBlindingDealerFunc, err := s.lsss.LiftDealerFunc(blindingDealerFunc, s.key.H())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to lift blinding dealer function")
	}
	verificationVector := liftedShareDealerFunc.Op(liftedBlindingDealerFunc)
	shares := hashmap.NewComparableFromNativeLike(
		maps.Collect(
			iterutils.Map2(
				dealtShares.Shares().Iter(),
				func(id sharing.ID, underlyingShare US) (sharing.ID, *Share[US, USV]) {
					blindingShare, _ := blindingShares.Shares().Get(id)
					return id, &Share[US, USV]{
						secret:   underlyingShare,
						blinding: blindingShare,
					}
				},
			),
		),
	)
	return &DealerOutput[US, USV, LFTUDF, LFTUS, LFTUSV, AC]{
			shares:             shares.Freeze(),
			verificationVector: verificationVector,
		}, &DealerFunc[ULDF, US, USV, AC]{
			shares:   shareDealerFunc,
			blinding: blindingDealerFunc,
		}, nil
}

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV, LFTW, LFTWV]) DealRandom(prng io.Reader) (*DealerOutput[US, USV, LFTUDF, LFTUS, LFTUSV, AC], W, error) {
	do, secret, _, err := s.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, *new(W), errs.Wrap(err).WithMessage("failed to deal random secret")
	}
	return do, secret, nil
}

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV, LFTW, LFTWV]) Reconstruct(shares ...*Share[US, USV]) (W, error) {
	reconstructed, err := s.lsss.Reconstruct(
		sliceutils.Map(
			shares,
			func(share *Share[US, USV]) US { return share.Secret() },
		)...,
	)
	if err != nil {
		return *new(W), errs.Wrap(err).WithMessage("failed to reconstruct secret")
	}
	return reconstructed, nil
}

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV, LFTW, LFTWV]) ReconstructAndVerify(reference LFTUDF, shares ...*Share[US, USV]) (W, error) {
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

func (s *Scheme[US, USV, W, WV, UDO, AC, ULDF, LFTUDF, LFTUS, LFTUSV, LFTW, LFTWV]) Verify(share *Share[US, USV], verificationVector LFTUDF) error {
	if !verificationVector.Accepts(s.AccessStructure()) {
		return sharing.ErrVerification.WithMessage("verification vector does not accept the scheme's access structure")
	}
	liftedShare := verificationVector.ShareOf(share.ID())

	// because some LSSS is not ideal, their shares may contain more than just a single field element. Therefore,
	// we need to operate on the full representation of the share.
	liftedShareRepr := slices.Collect(liftedShare.Repr())
	shareSecretRepr := slices.Collect(share.Secret().Repr())
	shareBlindingRepr := slices.Collect(share.Blinding().Repr())

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
		pedersenMessage := pedcom.NewMessage(shareSecretRepr[i])
		pedersenWitness, err := pedcom.NewWitness(shareBlindingRepr[i])
		if err != nil {
			return errs.Wrap(err).WithMessage("failed to create witness from share blinding component")
		}
		if err := verifier.Verify(commitment, pedersenMessage, pedersenWitness); err != nil {
			return errs.Wrap(err).WithMessage("share verification failed")
		}
	}
	return nil
}
