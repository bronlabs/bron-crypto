package pedersen

import (
	"io"
	"maps"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/shamir"
	"github.com/bronlabs/errs-go/errs"
)

// NewScheme creates a new Pedersen VSS scheme.
//
// Parameters:
//   - key: Pedersen commitment key containing generators g and h
//   - accessStructure: Threshold access structure defining quorum requirements
func NewScheme[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](key *pedcom.Key[E, S], accessStructure *accessstructures.Threshold) (*Scheme[E, S], error) {
	if accessStructure == nil {
		return nil, sharing.ErrIsNil.WithMessage("access structure is nil")
	}

	pedcomScheme, err := pedcom.NewScheme(key)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create pedersen scheme")
	}
	module := algebra.StructureMustBeAs[algebra.Module[E, S]](key.G().Structure())
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](module.ScalarStructure())
	shamirSSS, err := shamir.NewScheme(field, accessStructure)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create shamir scheme")
	}
	return &Scheme[E, S]{
		key:              key,
		commitmentScheme: pedcomScheme,
		shamirSSS:        shamirSSS,
	}, nil
}

// Scheme implements Pedersen's verifiable secret sharing with information-theoretic hiding.
type Scheme[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	key              *pedcom.Key[E, S]
	commitmentScheme commitments.Scheme[*pedcom.Key[E, S], *pedcom.Witness[S], *pedcom.Message[S], *pedcom.Commitment[E, S], *pedcom.Committer[E, S], *pedcom.Verifier[E, S]]
	shamirSSS        *shamir.Scheme[S]
}

// Name returns the canonical name of this scheme.
func (*Scheme[E, S]) Name() sharing.Name {
	return Name
}

// AccessStructure returns the threshold access structure.
func (s *Scheme[E, S]) AccessStructure() *accessstructures.Threshold {
	return s.shamirSSS.AccessStructure()
}

func (s *Scheme[E, S]) dealAllNonZeroShares(secret *Secret[S], prng io.Reader) (*shamir.DealerOutput[S], *shamir.Secret[S], shamir.DealerFunc[S], error) {
	if prng == nil {
		return nil, nil, nil, sharing.ErrIsNil.WithMessage("prng is nil")
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
			return nil, nil, nil, errs.Wrap(err).WithMessage("could not deal shares")
		}
	}
	return shamirShares, secret, secretPoly, nil
}

// DealAndRevealDealerFunc creates shares for the given secret and returns the dealing
// polynomials. Uses two polynomials: f(x) for the secret and r(x) for blinding.
// The verification vector contains Pedersen commitments g^{a_j}·h^{b_j}.
func (s *Scheme[E, S]) DealAndRevealDealerFunc(secret *Secret[S], prng io.Reader) (*DealerOutput[E, S], *DealerFunc[S], error) {
	if secret == nil {
		return nil, nil, sharing.ErrIsNil.WithMessage("secret is nil")
	}
	// Deal secret shares (can be zero)
	shamirShares, secretPoly, err := s.shamirSSS.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not deal secret shares")
	}
	// Deal blinding shares (must be non-zero for witness creation)
	blindingShares, _, blindingPoly, err := s.dealAllNonZeroShares(nil, prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not deal blinding shares")
	}
	dealerFunc := NewDealerFunc(secretPoly, blindingPoly)
	dealerFuncInTheExponent, err := liftDealerFuncToExp(dealerFunc, s.key.G(), s.key.H())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not lift direct sum of polynomials to exponent")
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

// Deal creates shares for the given secret along with a verification vector.
func (s *Scheme[E, S]) Deal(secret *Secret[S], prng io.Reader) (*DealerOutput[E, S], error) {
	shares, _, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not deal shares")
	}
	return shares, nil
}

// DealRandomAndRevealDealerFunc generates shares for a random secret and returns
// the dealing polynomials.
func (s *Scheme[E, S]) DealRandomAndRevealDealerFunc(prng io.Reader) (*DealerOutput[E, S], *Secret[S], *DealerFunc[S], error) {
	if prng == nil {
		return nil, nil, nil, sharing.ErrIsNil.WithMessage("prng is nil")
	}
	value, err := s.shamirSSS.Field().Random(prng)
	if err != nil {
		return nil, nil, nil, errs.Wrap(err).WithMessage("could not sample random field element")
	}
	secret := NewSecret(value)
	shares, poly, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, nil, errs.Wrap(err).WithMessage("could not create shares")
	}
	return shares, secret, poly, nil
}

// DealRandom generates shares for a randomly sampled secret.
func (s *Scheme[E, S]) DealRandom(prng io.Reader) (*DealerOutput[E, S], *Secret[S], error) {
	if prng == nil {
		return nil, nil, sharing.ErrIsNil.WithMessage("prng is nil")
	}
	shares, secret, _, err := s.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not deal random shares")
	}
	return shares, secret, nil
}

// Reconstruct recovers the secret from a set of shares using Lagrange interpolation.
// Only the secret component f(i) of each share is used; blinding factors are discarded.
func (s *Scheme[E, S]) Reconstruct(shares ...*Share[S]) (*Secret[S], error) {
	shamirShares, _ := sliceutils.MapOrError(shares, func(sh *Share[S]) (*shamir.Share[S], error) { return shamir.NewShare(sh.ID(), sh.secret.Value(), nil) })
	secret, err := s.shamirSSS.Reconstruct(shamirShares...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not reconstruct secret from shares")
	}
	return secret, nil
}

// ReconstructAndVerify recovers the secret and verifies each share against
// the verification vector before reconstruction.
func (s *Scheme[E, S]) ReconstructAndVerify(vector VerificationVector[E, S], shares ...*Share[S]) (*Secret[S], error) {
	reconstructed, err := s.Reconstruct(shares...)
	if err != nil {
		return nil, err
	}
	for i, share := range shares {
		if err := s.Verify(share, vector); err != nil {
			return nil, errs.Wrap(err).WithMessage("verification failed for share %d", i)
		}
	}
	return reconstructed, nil
}

// Verify checks that a share (s_i, t_i) is consistent with the verification vector.
// Returns nil if g^{s_i}·h^{t_i} equals the evaluation of the verification vector at the share's ID.
func (s *Scheme[E, S]) Verify(share *Share[S], vector VerificationVector[E, S]) error {
	if vector == nil {
		return sharing.ErrIsNil.WithMessage("verification vector is nil")
	}
	if uint(vector.Degree()+1) != s.AccessStructure().Threshold() {
		return sharing.ErrVerification.WithMessage("verification vector degree does not match threshold")
	}
	commitment, err := pedcom.NewCommitment(vector.Eval(s.shamirSSS.SharingIDToLagrangeNode(share.ID())))
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create commitment from recomputed value")
	}
	verifier, err := s.commitmentScheme.Verifier()
	if err != nil {
		return errs.Wrap(err).WithMessage("could not create verifier")
	}
	if err := verifier.Verify(commitment, share.secret, share.blinding); err != nil {
		return errs.Wrap(err).WithMessage("could not verify commitment")
	}
	return nil
}

// ConvertShareToAdditive converts this Shamir share to an additive share by multiplying
// by the appropriate Lagrange coefficient. The resulting additive shares can
// be summed to reconstruct the secret.
func (*Scheme[E, S]) ConvertShareToAdditive(s *Share[S], quorum *accessstructures.Unanimity) (*additive.Share[S], error) {
	return s.ToAdditive(quorum)
}
