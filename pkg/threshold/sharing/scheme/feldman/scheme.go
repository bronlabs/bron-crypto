package feldman

import (
	"io"
	"maps"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/errs-go/errs"
)

// Scheme implements Feldman's verifiable secret sharing.
type Scheme[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	basePoint E
	shamirSSS *shamir.Scheme[FE]
}

// NewScheme creates a new Feldman VSS scheme.
//
// Parameters:
//   - basePoint: Generator g of the group used for verification commitments
//   - threshold: Minimum shares required for reconstruction (must be ≥ 2)
//   - shareholders: Set of shareholder IDs
func NewScheme[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](basePoint E, threshold uint, shareholders ds.Set[sharing.ID]) (*Scheme[E, FE], error) {
	if utils.IsNil(basePoint) {
		return nil, ErrIsNil.WithMessage("base point is nil")
	}

	group := algebra.StructureMustBeAs[algebra.PrimeGroup[E, FE]](basePoint.Structure())
	f := algebra.StructureMustBeAs[algebra.PrimeField[FE]](group.ScalarStructure())
	shamirScheme, err := shamir.NewScheme(f, threshold, shareholders)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create shamir scheme")
	}
	return &Scheme[E, FE]{
		basePoint: basePoint,
		shamirSSS: shamirScheme,
	}, nil
}

// Name returns the canonical name of this scheme.
func (*Scheme[E, FE]) Name() sharing.Name {
	return Name
}

// AccessStructure returns the threshold access structure.
func (d *Scheme[E, FE]) AccessStructure() *sharing.ThresholdAccessStructure {
	return d.shamirSSS.AccessStructure()
}

// DealRandom generates shares for a randomly sampled secret.
func (d *Scheme[E, FE]) DealRandom(prng io.Reader) (*DealerOutput[E, FE], *Secret[FE], error) {
	out, secret, _, err := d.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not deal random shares")
	}
	return out, secret, nil
}

// DealRandomAndRevealDealerFunc generates shares for a random secret and returns
// the dealing polynomial.
func (d *Scheme[E, FE]) DealRandomAndRevealDealerFunc(prng io.Reader) (output *DealerOutput[E, FE], secret *Secret[FE], dealerFunc DealerFunc[FE], err error) {
	if prng == nil {
		return nil, nil, nil, ErrIsNil.WithMessage("prng is nil")
	}
	value, err := d.shamirSSS.Field().Random(prng)
	if err != nil {
		return nil, nil, nil, errs.Wrap(err).WithMessage("could not sample field element")
	}
	secret = NewSecret(value)
	out, poly, err := d.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, nil, errs.Wrap(err).WithMessage("could not create shares")
	}
	return out, secret, poly, nil
}

// Deal creates shares for the given secret along with a verification vector.
func (d *Scheme[E, FE]) Deal(secret *Secret[FE], prng io.Reader) (*DealerOutput[E, FE], error) {
	out, _, err := d.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not deal shares")
	}
	return out, nil
}

// DealAndRevealDealerFunc creates shares and returns the dealing polynomial.
// The verification vector is computed as g^{f(x)} where f is the polynomial.
func (d *Scheme[E, FE]) DealAndRevealDealerFunc(secret *Secret[FE], prng io.Reader) (*DealerOutput[E, FE], DealerFunc[FE], error) {
	shamirShares, poly, err := d.shamirSSS.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not create shamir shares")
	}
	verificationVector, err := polynomials.LiftPolynomial(poly, d.basePoint)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("could not lift polynomial to exponent")
	}
	shares := hashmap.NewComparableFromNativeLike(maps.Collect(shamirShares.Shares().Iter())).Freeze()
	return &DealerOutput[E, FE]{
		shares: shares,
		v:      verificationVector,
	}, poly, nil
}

// Reconstruct recovers the secret from a set of shares using Lagrange interpolation.
func (d *Scheme[E, FE]) Reconstruct(shares ...*Share[FE]) (*Secret[FE], error) {
	secret, err := d.shamirSSS.Reconstruct(shares...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not reconstruct secret from shares")
	}
	return secret, nil
}

// ReconstructAndVerify recovers the secret and verifies each share against
// the verification vector before reconstruction.
func (d *Scheme[E, FE]) ReconstructAndVerify(reference VerificationVector[E, FE], shares ...*Share[FE]) (*Secret[FE], error) {
	reconstructed, err := d.Reconstruct(shares...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not reconstruct secret without verification")
	}
	for i, share := range shares {
		if err := d.Verify(share, reference); err != nil {
			return nil, errs.Wrap(err).WithMessage("verification failed for share %d", i)
		}
	}
	return reconstructed, nil
}

// Verify checks that a share is consistent with the verification vector.
// Returns nil if g^{share} equals the evaluation of the verification vector at the share's ID.
func (d *Scheme[E, FE]) Verify(share *Share[FE], reference VerificationVector[E, FE]) error {
	if reference == nil {
		return ErrIsNil.WithMessage("verification vector is nil")
	}
	if reference.Degree()+1 != int(d.shamirSSS.AccessStructure().Threshold()) {
		return ErrVerification.WithMessage("verification vector degree %d does not match expected degree %d", reference.Degree(), d.shamirSSS.AccessStructure().Threshold()-1)
	}
	x := d.shamirSSS.SharingIDToLagrangeNode(share.ID())
	yInExponent := reference.Eval(x)
	shareInExponent := d.basePoint.ScalarOp(share.Value())
	if !yInExponent.Equal(shareInExponent) {
		return ErrVerification.WithMessage("verification vector does not match share in exponent")
	}
	return nil
}
