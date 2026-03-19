package feldman

import (
	"io"
	"maps"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
)

// Scheme implements Feldman's verifiable secret sharing over a Karchmer-Wigderson
// MSP-based LSSS. It supports any linear access structure (threshold, CNF,
// hierarchical, boolean-expression, etc.) rather than only threshold structures.
//
// The dealer samples a random column r (with r[0] = secret), computes shares
// λ = M · r via the MSP, and publishes the verification vector V = [r]G.
// Any party can verify a share by checking [λ_i]G == M_i · V, where M_i
// denotes the MSP rows belonging to shareholder i.
type Scheme[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	group algebra.PrimeGroup[E, FE]
	lsss  *kw.Scheme[FE]
}

// NewScheme creates a new Feldman VSS scheme over the given prime-order group
// and linear access structure. The scalar field is derived from the group.
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

// Name returns the canonical name of this scheme.
func (*Scheme[E, FE]) Name() sharing.Name {
	return Name
}

// AccessStructure returns the linear access structure underlying this scheme.
func (s *Scheme[E, FE]) AccessStructure() accessstructures.Linear {
	return s.lsss.AccessStructure()
}

// DealRandom generates shares for a uniformly random secret and returns
// both the dealer output (shares + verification vector) and the secret.
func (s *Scheme[E, FE]) DealRandom(prng io.Reader) (*DealerOutput[E, FE], *kw.Secret[FE], error) {
	do, secret, _, err := s.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to deal shares")
	}
	return do, secret, nil
}

// DealRandomAndRevealDealerFunc generates shares for a uniformly random secret
// and additionally returns the DealerFunc (the random column r and share vector
// λ = M · r). The DealerFunc is secret dealer state and must not be published.
func (s *Scheme[E, FE]) DealRandomAndRevealDealerFunc(prng io.Reader) (*DealerOutput[E, FE], *kw.Secret[FE], *DealerFunc[FE], error) {
	lsssOutput, secret, df, err := s.lsss.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, nil, errs.Wrap(err).WithMessage("failed to deal shares")
	}

	verificationMatrix, err := mat.Lift(df.RandomColumn(), s.group.Generator())
	if err != nil {
		return nil, nil, nil, errs.Wrap(err).WithMessage("failed to lift matrix for verification commitments")
	}
	verificationVector, err := NewVerificationVector(verificationMatrix, s.lsss.MSP())
	if err != nil {
		return nil, nil, nil, errs.Wrap(err).WithMessage("failed to create verification vector")
	}
	shares := hashmap.NewComparableFromNativeLike(maps.Collect(lsssOutput.Shares().Iter())).Freeze()

	return &DealerOutput[E, FE]{
		shares: shares,
		v:      verificationVector,
	}, secret, df, nil
}

// Deal creates shares for the given secret and returns the dealer output
// containing both the shares and the public verification vector V = [r]G.
func (s *Scheme[E, FE]) Deal(secret *kw.Secret[FE], prng io.Reader) (*DealerOutput[E, FE], error) {
	do, _, err := s.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to deal shares")
	}
	return do, nil
}

// DealAndRevealDealerFunc creates shares for the given secret and additionally
// returns the DealerFunc. The verification vector is computed as V = [r]G,
// where r is the random column from the KW dealing.
func (s *Scheme[E, FE]) DealAndRevealDealerFunc(secret *kw.Secret[FE], prng io.Reader) (*DealerOutput[E, FE], *DealerFunc[FE], error) {
	lsssOutput, df, err := s.lsss.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to deal shares")
	}

	verificationMatrix, err := mat.Lift(df.RandomColumn(), s.group.Generator())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to lift matrix for verification commitments")
	}
	verificationVector, err := NewVerificationVector(verificationMatrix, s.lsss.MSP())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to create verification vector")
	}
	shares := hashmap.NewComparableFromNativeLike(maps.Collect(lsssOutput.Shares().Iter())).Freeze()

	return &DealerOutput[E, FE]{
		shares: shares,
		v:      verificationVector,
	}, df, nil
}

// Reconstruct recovers the secret from a qualified set of shares using the
// MSP reconstruction vector.
func (s *Scheme[E, FE]) Reconstruct(shares ...*kw.Share[FE]) (*kw.Secret[FE], error) {
	out, err := s.lsss.Reconstruct(shares...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to reconstruct secret")
	}
	return out, nil
}

// ReconstructAndVerify recovers the secret and verifies every provided share
// against the verification vector. If any share fails verification the
// reconstructed value is discarded and an error is returned.
func (s *Scheme[E, FE]) ReconstructAndVerify(reference *VerificationVector[E, FE], shares ...*kw.Share[FE]) (*kw.Secret[FE], error) {
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

// Verify checks that a scalar share is consistent with the public verification
// vector V. It computes the expected lifted share M_i · V (via the left module
// action of the shareholder's MSP rows on V) and compares it against the
// manually lifted scalar share [λ_i]G. Returns nil if and only if the two
// agree.
func (s *Scheme[E, FE]) Verify(share *kw.Share[FE], reference *VerificationVector[E, FE]) error {
	if share == nil {
		return sharing.ErrIsNil.WithMessage("share is nil")
	}

	// Dimension enforcement in the left module action implicitly rejects
	// verification vectors whose length does not match the MSP column count D,
	// preventing the Dahlgren attack
	// (https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/).
	// This is the generalisation of the polynomial degree check in classical
	// Feldman VSS.
	liftedDealerFunc, err := NewLiftedDealerFunc(reference, s.lsss.MSP())
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create lifted dealer function from verification vector")
	}

	// Evaluate my lifted share from the reference
	liftedShare, err := liftedDealerFunc.ShareOf(share.ID())
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to compute lifted share from verification vector for share of shareholder %d", share.ID())
	}

	// Manually lift the share to the basepoint
	manuallyLiftedShare, err := LiftShare(share, s.group.Generator())
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to manually lift share for shareholder %d", share.ID())
	}

	if !liftedShare.Equal(manuallyLiftedShare) {
		return sharing.ErrVerification.WithMessage("share verification failed for shareholder %d", share.ID())
	}
	return nil
}

// ConvertShareToAdditive converts a KW share into an additive share relative
// to the given quorum. The quorum must be a qualified set under the access
// structure. The resulting additive shares can be summed to recover the secret.
func (s *Scheme[E, FE]) ConvertShareToAdditive(share *kw.Share[FE], quorum *unanimity.Unanimity) (*additive.Share[FE], error) {
	out, err := s.lsss.ConvertShareToAdditive(share, quorum)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not convert share to additive share")
	}
	return out, nil
}
