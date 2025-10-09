package feldman

import (
	"io"
	"maps"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

type Scheme[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]] struct {
	basePoint E
	shamirSSS *shamir.Scheme[FE]
}

func NewScheme[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](basePoint E, threshold uint, shareholders ds.Set[sharing.ID]) (*Scheme[E, FE], error) {
	if utils.IsNil(basePoint) {
		return nil, errs.NewIsNil("base point is nil")
	}

	group := algebra.StructureMustBeAs[algebra.PrimeGroup[E, FE]](basePoint.Structure())
	f := algebra.StructureMustBeAs[algebra.PrimeField[FE]](group.ScalarStructure())
	shamirScheme, err := shamir.NewScheme(f, threshold, shareholders)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create shamir scheme")
	}
	return &Scheme[E, FE]{
		basePoint: basePoint,
		shamirSSS: shamirScheme,
	}, nil
}

func (*Scheme[E, FE]) Name() sharing.Name {
	return Name
}

func (d *Scheme[E, FE]) AccessStructure() *AccessStructure {
	return d.shamirSSS.AccessStructure()
}

func (d *Scheme[E, FE]) DealRandom(prng io.Reader) (*DealerOutput[E, FE], *Secret[FE], error) {
	out, secret, _, err := d.DealRandomAndRevealDealerFunc(prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not deal random shares")
	}
	return out, secret, nil
}

func (d *Scheme[E, FE]) DealRandomAndRevealDealerFunc(prng io.Reader) (*DealerOutput[E, FE], *Secret[FE], DealerFunc[FE], error) {
	if prng == nil {
		return nil, nil, nil, errs.NewIsNil("prng is nil")
	}
	value, err := d.shamirSSS.Field().Random(prng)
	if err != nil {
		return nil, nil, nil, errs.WrapRandomSample(err, "could not sample field element")
	}
	secret := NewSecret(value)
	out, poly, err := d.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not create shares")
	}
	return out, secret, poly, nil
}

func (d *Scheme[E, FE]) Deal(secret *Secret[FE], prng io.Reader) (*DealerOutput[E, FE], error) {
	out, _, err := d.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not deal shares")
	}
	return out, nil
}

func (d *Scheme[E, FE]) DealAndRevealDealerFunc(secret *Secret[FE], prng io.Reader) (*DealerOutput[E, FE], DealerFunc[FE], error) {
	shamirShares, poly, err := d.shamirSSS.DealAndRevealDealerFunc(secret, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create shamir shares")
	}
	verificationVector, err := polynomials.LiftPolynomial(poly, d.basePoint)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not lift polynomial to exponent")
	}
	shares := hashmap.NewComparableFromNativeLike(maps.Collect(shamirShares.Shares().Iter())).Freeze()
	return &DealerOutput[E, FE]{
		shares: shares,
		v:      verificationVector,
	}, poly, nil
}

func (d *Scheme[E, FE]) Reconstruct(shares ...*Share[FE]) (*Secret[FE], error) {
	secret, err := d.shamirSSS.Reconstruct(shares...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not reconstruct secret from shares")
	}
	return secret, nil
}

func (d *Scheme[E, FE]) ReconstructAndVerify(reference VerificationVector[E, FE], shares ...*Share[FE]) (*Secret[FE], error) {
	reconstructed, err := d.Reconstruct(shares...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not reconstruct secret without verification")
	}
	for i, share := range shares {
		if err := d.Verify(share, reference); err != nil {
			return nil, errs.WrapFailed(err, "verification failed for share %d", i)
		}
	}
	return reconstructed, nil
}

func (d *Scheme[E, FE]) Verify(share *Share[FE], reference VerificationVector[E, FE]) error {
	if reference == nil {
		return errs.NewIsNil("verification vector is nil")
	}
	x := d.shamirSSS.SharingIDToLagrangeNode(share.ID())
	yInExponent := reference.Eval(x)
	shareInExponent := d.basePoint.ScalarOp(share.Value())
	if !yInExponent.Equal(shareInExponent) {
		return errs.NewVerification("verification vector does not match share in exponent")
	}
	return nil
}
