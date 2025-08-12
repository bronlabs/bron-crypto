package feldman

import (
	"io"
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

type (
	Field[FE FieldElement[FE]]                                              = shamir.PrimeField[FE]
	FieldElement[FE algebra.PrimeFieldElement[FE]]                          = shamir.FieldElement[FE]
	DealerFunc[FE FieldElement[FE]]                                         = shamir.DealerFunc[FE]
	BoundedElement[E algebra.PrimeGroupElement[E, FE], FE FieldElement[FE]] = algebra.PrimeGroupElement[E, FE]
	VerificationVector[E BoundedElement[E, FE], FE FieldElement[FE]]        = polynomials.ModuleValuedPolynomial[E, FE]
	AccessStructure                                                         = shamir.AccessStructure
)

const Name sharing.Name = "Feldman's Verifiable Secret Sharing Scheme"

var (
	NewAccessStructure = shamir.NewAccessStructure
)

func NewScheme[E BoundedElement[E, FE], FE FieldElement[FE]](f Field[FE], basePoint E, threshold uint, shareholders ds.Set[sharing.ID]) (*Scheme[E, FE], error) {
	if utils.IsNil(basePoint) {
		return nil, errs.NewIsNil("base point is nil")
	}
	shamirScheme, err := shamir.NewScheme(f, threshold, shareholders)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not create shamir scheme")
	}
	return &Scheme[E, FE]{
		basePoint: basePoint,
		shamirSSS: shamirScheme,
	}, nil
}

type Scheme[E BoundedElement[E, FE], FE FieldElement[FE]] struct {
	basePoint E
	shamirSSS *shamir.Scheme[FE]
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
	verificationVector, err := polynomials.LiftToExponent(poly, d.basePoint)
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

func NewLiftedShare[E BoundedElement[E, FE], FE FieldElement[FE]](id sharing.ID, v E) (*LiftedShare[E, FE], error) {
	if utils.IsNil(v) {
		return nil, errs.NewIsNil("value is nil")
	}
	group, ok := v.Structure().(algebra.PrimeGroup[E, FE])
	if !ok {
		return nil, errs.NewType("share value does not implement PrimeGroup interface")
	}
	sf, ok := group.ScalarStructure().(algebra.PrimeField[FE])
	if !ok {
		return nil, errs.NewType("share value does not implement PrimeField interface")
	}
	return &LiftedShare[E, FE]{
		group: group,
		sf:    sf,
		id:    id,
		v:     v,
	}, nil
}

type LiftedShare[E BoundedElement[E, FE], FE FieldElement[FE]] struct {
	group algebra.PrimeGroup[E, FE]
	sf    algebra.PrimeField[FE]
	id    sharing.ID
	v     E
}

func (s *LiftedShare[E, FE]) ID() sharing.ID {
	return s.id
}

func (s *LiftedShare[E, FE]) Value() E {
	return s.v
}

func (s *LiftedShare[E, FE]) ToAdditive(qualifiedSet *sharing.MinimalQualifiedAccessStructure) (*additive.Share[E], error) {
	if qualifiedSet == nil {
		return nil, errs.NewIsNil("qualified set is nil")
	}
	if !qualifiedSet.Shareholders().Contains(s.id) {
		return nil, errs.NewMembership("share ID %d is not a valid shareholder", s.id)
	}
	lambdas, err := shamir.LagrangeCoefficients(s.sf, qualifiedSet.Shareholders().List()...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute Lagrange coefficients")
	}
	lambda_i, exists := lambdas.Get(s.id)
	if !exists {
		return nil, errs.NewMembership("share ID %d is not a valid shareholder", s.id)
	}
	converted := s.v.ScalarOp(lambda_i)
	return additive.NewShare(s.id, converted, qualifiedSet)
}

type SharesInExponent[E BoundedElement[E, FE], FE FieldElement[FE]] []*LiftedShare[E, FE]

func (s SharesInExponent[E, FE]) ReconstructAsAdditive() (E, error) {
	if len(s) == 0 {
		return *new(E), errs.NewArgument("no shares provided for reconstruction")
	}
	group := s[0].group
	sf := s[0].sf
	qualifiedSet, err := sharing.NewMinimalQualifiedAccessStructure(
		hashset.NewComparable(
			slices.Collect(
				iterutils.Map(
					slices.Values(s),
					func(share *LiftedShare[E, FE]) sharing.ID { return share.ID() },
				),
			)...,
		).Freeze(),
	)
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not create qualified set from shares")
	}
	lambdas, err := shamir.LagrangeCoefficients(sf, qualifiedSet.Shareholders().List()...)
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not compute Lagrange coefficients")
	}
	converted := make([]*additive.Share[E], 0, len(s))
	for _, share := range s {
		lambda_i, exists := lambdas.Get(share.ID())
		if !exists {
			return *new(E), errs.NewMembership("share ID %d is not a valid shareholder", share.ID())
		}
		si, err := additive.NewShare(share.ID(), share.v.ScalarOp(lambda_i), nil)
		if err != nil {
			return *new(E), errs.WrapFailed(err, "could not create additive share from share in exponent")
		}
		converted = append(converted, si)
	}
	additiveScheme, err := additive.NewScheme(group, qualifiedSet.Shareholders())
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not create additive scheme")
	}
	reconstructed, err := additiveScheme.Reconstruct(converted...)
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not reconstruct additive share")
	}
	return reconstructed.Value(), nil
}

func NewShare[FE FieldElement[FE]](id sharing.ID, v FE, ac *AccessStructure) (*Share[FE], error) {
	return shamir.NewShare(id, v, ac)
}

type Share[FE FieldElement[FE]] = shamir.Share[FE]

func NewSecret[FE FieldElement[FE]](value FE) *Secret[FE] {
	return shamir.NewSecret(value)
}

type Secret[FE FieldElement[FE]] = shamir.Secret[FE]

type DealerOutput[E BoundedElement[E, FE], FE FieldElement[FE]] struct {
	shares ds.Map[sharing.ID, *Share[FE]]
	v      VerificationVector[E, FE]
}

func (d *DealerOutput[E, FE]) Shares() ds.Map[sharing.ID, *Share[FE]] {
	if d == nil {
		return nil
	}
	return d.shares
}

func (d *DealerOutput[E, FE]) VerificationMaterial() VerificationVector[E, FE] {
	if d == nil {
		return nil
	}
	return d.v
}

func _[E BoundedElement[E, FE], FE FieldElement[FE]]() {
	var (
		_ sharing.LinearShare[*Share[FE], FE, *additive.Share[FE], FE, *AccessStructure] = (*Share[FE])(nil)
		_ sharing.LinearlyShareableSecret[*Secret[FE], FE]                               = (*Secret[FE])(nil)

		_ sharing.ThresholdSSS[*Share[FE], *Secret[FE], *DealerOutput[E, FE], *AccessStructure]                                = (*Scheme[E, FE])(nil)
		_ sharing.VSSS[*Share[FE], *Secret[FE], VerificationVector[E, FE], *DealerOutput[E, FE], *AccessStructure]             = (*Scheme[E, FE])(nil)
		_ sharing.PolynomialLSSS[*Share[FE], FE, *additive.Share[FE], *Secret[FE], FE, *DealerOutput[E, FE], *AccessStructure] = (*Scheme[E, FE])(nil)
	)
}
