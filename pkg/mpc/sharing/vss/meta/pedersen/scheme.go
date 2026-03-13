package pedersen

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
)

// Scheme implements Pedersen's verifiable secret sharing over a
// Karchmer-Wigderson MSP-based LSSS. It supports any linear access structure
// (threshold, CNF, hierarchical, boolean-expression, etc.) rather than only
// threshold structures.
//
// The scheme is computationally binding under the discrete logarithm
// assumption and perfectly hiding: the verification vector reveals no
// information about the secret, even to a computationally unbounded adversary.
// This is achieved by committing to each random column entry with a Pedersen
// commitment Com(r_g_j, r_h_j) = [r_g_j]G + [r_h_j]H, where G and H are
// independent generators whose discrete-log relation is unknown.
type Scheme[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	commitmentScheme *pedcom.Scheme[E, S]
	lsss             *kw.Scheme[S]
}

// NewScheme creates a new Pedersen VSS scheme over the given Pedersen
// commitment key and linear access structure. The scalar field is derived
// from the key's group. The key must consist of two independent generators
// (G, H) of a prime-order group; the security of the hiding property relies
// on the discrete-log relation between G and H being unknown.
func NewScheme[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](key *pedcom.Key[E, S], accessStructure accessstructures.Linear) (*Scheme[E, S], error) {
	if key == nil {
		return nil, sharing.ErrIsNil.WithMessage("pedersen commitment key is nil")
	}
	if accessStructure == nil {
		return nil, sharing.ErrIsNil.WithMessage("access structure is nil")
	}

	commitmentScheme, err := pedcom.NewScheme(key)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create Pedersen commitment scheme")
	}

	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](key.Group().ScalarStructure())

	lsss, err := kw.NewScheme(field, accessStructure)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create LSSS scheme")
	}
	return &Scheme[E, S]{
		commitmentScheme: commitmentScheme,
		lsss:             lsss,
	}, nil
}

// Name returns the canonical name of this scheme.
func (*Scheme[E, S]) Name() sharing.Name {
	return Name
}

// AccessStructure returns the linear access structure underlying this scheme.
func (s *Scheme[E, S]) AccessStructure() accessstructures.Linear {
	return s.lsss.AccessStructure()
}

// Deal creates shares for the given secret and returns the dealer output
// containing both the shares and the public verification vector
// V = [r_g]G + [r_h]H.
func (s *Scheme[E, S]) Deal(secret *kw.Secret[S], prng io.Reader) (*DealerOutput[E, S], error) {
	do, _, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not deal and reveal dealer func")
	}
	return do, nil
}

// DealAndRevealDealerFunc creates shares for the given secret and additionally
// returns the DealerFunc containing both the secret and blinding random
// columns. The verification vector is computed as V = [r_g]G + [r_h]H.
// The DealerFunc is secret dealer state and must not be published.
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

// DealRandom generates shares for a uniformly random secret and returns
// both the dealer output (shares + verification vector) and the secret.
func (s *Scheme[E, S]) DealRandom(prng io.Reader) (*DealerOutput[E, S], *kw.Secret[S], error) {
	do, secret, _, err := s.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not deal random shares and reveal dealer func")
	}
	return do, secret, nil
}

// DealRandomAndRevealDealerFunc generates shares for a uniformly random secret
// and additionally returns the DealerFunc (the secret and blinding random
// columns and the share vectors). The DealerFunc is secret dealer state and
// must not be published.
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

// Reconstruct recovers the secret from a qualified set of shares using the
// MSP reconstruction vector. Only the secret component of each share is used;
// blinding factors are discarded.
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

// ReconstructAndVerify recovers the secret and verifies every provided share
// against the verification vector. If any share fails verification the
// reconstructed value is discarded and an error is returned.
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

// Verify checks that a share is consistent with the public verification
// vector V. It computes the expected lifted share M_i · V (via the left
// module action of the shareholder's MSP rows on V) and compares it against
// the Pedersen commitments Com(secret_j, blinding_j) = [secret_j]G +
// [blinding_j]H computed from the share's scalar components. Returns nil if
// and only if the two agree.
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

// ConvertShareToAdditive converts a Pedersen share into an additive share
// relative to the given quorum. The quorum must be a qualified set under the
// access structure. Only the secret component is converted; blinding factors
// are discarded. The resulting additive shares can be summed to recover the
// secret.
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
