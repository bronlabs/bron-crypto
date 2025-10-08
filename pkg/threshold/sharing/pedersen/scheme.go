package pedersen

import (
	"io"
	"maps"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

func NewScheme[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](key *pedcom.Key[E, S], threshold uint, shareholders ds.Set[sharing.ID]) (*Scheme[E, S], error) {
	pedcomScheme, err := pedcom.NewScheme(key)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create pedersen scheme")
	}
	field := key.G().Structure().(algebra.Module[E, S]).ScalarStructure().(algebra.PrimeField[S])
	shamirSSS, err := shamir.NewScheme(field, threshold, shareholders)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create shamir scheme")
	}
	return &Scheme[E, S]{
		key:              key,
		commitmentScheme: pedcomScheme,
		shamirSSS:        shamirSSS,
	}, nil
}

type Scheme[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	key              *pedcom.Key[E, S]
	commitmentScheme commitments.Scheme[*pedcom.Witness[S], *pedcom.Message[S], *pedcom.Commitment[E, S]]
	shamirSSS        *shamir.Scheme[S]
}

func (s *Scheme[E, S]) Name() sharing.Name {
	return Name
}

func (s *Scheme[E, S]) AccessStructure() *AccessStructure {
	return s.shamirSSS.AccessStructure()
}

func (s *Scheme[E, S]) dealAllNonZeroShares(secret *Secret[S], prng io.Reader) (*shamir.DealerOutput[S], *shamir.Secret[S], shamir.DealerFunc[S], error) {
	if prng == nil {
		return nil, nil, nil, errs.NewIsNil("prng is nil")
	}
	var shamirShares *shamir.DealerOutput[S]
	var secretPoly shamir.DealerFunc[S]
	var err error
	for shamirShares == nil || sliceutils.Any(
		shamirShares.Shares().Values(), func(share *shamir.Share[S]) bool { return share.Value().IsZero() },
	) {
		if secret != nil {
			shamirShares, secretPoly, err = s.shamirSSS.DealAndRevealDealerFunc(secret, prng)
		} else {
			shamirShares, secret, secretPoly, err = s.shamirSSS.DealRandomAndRevealDealerFunc(prng)
		}
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "could not deal shares")
		}
	}
	return shamirShares, secret, secretPoly, nil
}

func (s *Scheme[E, S]) DealAndRevealDealerFunc(secret *Secret[S], prng io.Reader) (*DealerOutput[E, S], *DealerFunc[S], error) {
	if secret == nil {
		return nil, nil, errs.NewIsNil("secret is nil")
	}
	// Deal secret shares (can be zero)
	shamirShares, secretPoly, err := s.shamirSSS.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not deal secret shares")
	}
	// Deal blinding shares (must be non-zero for witness creation)
	blindingShares, _, blindingPoly, err := s.dealAllNonZeroShares(nil, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not deal blinding shares")
	}
	dealerFunc := NewDealerFunc(secretPoly, blindingPoly)
	dealerFuncInTheExponent, err := liftDealerFuncToExp(dealerFunc, s.key.G(), s.key.H())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not lift direct sum of polynomials to exponent")
	}
	verificationVector := dealerFuncInTheExponent.VerificationVector()
	shares := hashmap.NewComparableFromNativeLike(
		maps.Collect(
			iterutils.Map2(
				shamirShares.Shares().Iter(),
				func(id sharing.ID, shamirShare *shamir.Share[S]) (sharing.ID, *Share[S]) {
					blindingShare, _ := blindingShares.Shares().Get(id)
					message := pedcom.NewMessage(shamirShare.Value())
					witness, _ := pedcom.NewWitness(blindingShare.Value())
					share, _ := NewShare(id, message, witness, nil)
					return id, share
				},
			),
		),
	)
	return &DealerOutput[E, S]{
		shares: shares.Freeze(),
		v:      verificationVector,
	}, dealerFunc, nil
}

func (s *Scheme[E, S]) Deal(secret *Secret[S], prng io.Reader) (*DealerOutput[E, S], error) {
	shares, _, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not deal shares")
	}
	return shares, nil
}

func (s *Scheme[E, S]) DealRandomAndRevealDealerFunc(prng io.Reader) (*DealerOutput[E, S], *Secret[S], *DealerFunc[S], error) {
	if prng == nil {
		return nil, nil, nil, errs.NewIsNil("prng is nil")
	}
	value, err := s.shamirSSS.Field().Random(prng)
	if err != nil {
		return nil, nil, nil, errs.WrapRandomSample(err, "could not sample random field element")
	}
	secret := NewSecret(value)
	shares, poly, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not create shares")
	}
	return shares, secret, poly, nil
}

func (s *Scheme[E, S]) DealRandom(prng io.Reader) (*DealerOutput[E, S], *Secret[S], error) {
	if prng == nil {
		return nil, nil, errs.NewIsNil("prng is nil")
	}
	shares, secret, _, err := s.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not deal random shares")
	}
	return shares, secret, nil
}

func (s *Scheme[E, S]) Reconstruct(shares ...*Share[S]) (*Secret[S], error) {
	shamirShares, _ := sliceutils.MapErrFunc(shares, func(sh *Share[S]) (*shamir.Share[S], error) { return shamir.NewShare(sh.ID(), sh.secret.Value(), nil) })
	secret, err := s.shamirSSS.Reconstruct(shamirShares...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not reconstruct secret from shares")
	}
	return secret, nil
}

func (s *Scheme[E, S]) ReconstructAndVerify(vector VerificationVector[E, S], shares ...*Share[S]) (*Secret[S], error) {
	reconstructed, err := s.Reconstruct(shares...)
	if err != nil {
		return nil, err
	}
	for i, share := range shares {
		if err := s.Verify(share, vector); err != nil {
			return nil, errs.WrapVerification(err, "verification failed for share %d", i)
		}
	}
	return reconstructed, nil
}

func (s *Scheme[E, S]) Verify(share *Share[S], vector VerificationVector[E, S]) error {
	if vector == nil {
		return errs.NewIsNil("verification vector is nil")
	}
	commitment, err := pedcom.NewCommitment(vector.Eval(s.shamirSSS.SharingIDToLagrangeNode(share.ID())))
	if err != nil {
		return errs.WrapSerialisation(err, "could not create commitment from recomputed value")
	}
	verifier := s.commitmentScheme.Verifier()
	if err := verifier.Verify(commitment, share.secret, share.blinding); err != nil {
		return errs.WrapVerification(err, "could not verify commitment")
	}
	return nil
}
