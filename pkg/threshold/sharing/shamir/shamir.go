package shamir

import (
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/polynomials"
	"github.com/bronlabs/krypton-primitives/pkg/base/polynomials/interpolation/lagrange"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing"
)

var (
	_ sharing.LinearScheme[*Share, curves.Scalar, curves.Scalar] = (*Scheme)(nil)
)

type Scheme struct {
	Threshold uint
	Total     uint
	Curve     curves.Curve
}

func NewScheme(threshold, total uint, curve curves.Curve) (*Scheme, error) {
	err := validateInputs(threshold, total, curve)
	if err != nil {
		return nil, errs.WrapArgument(err, "failed to validate inputs")
	}

	return &Scheme{
		Threshold: threshold,
		Total:     total,
		Curve:     curve,
	}, nil
}

func (d *Scheme) Deal(secret curves.Scalar, prng io.Reader) (map[types.SharingID]*Share, error) {
	if secret == nil {
		return nil, errs.NewIsNil("secret is nil")
	}
	shares, _, err := d.GeneratePolynomialAndShares(secret, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate polynomial and shares")
	}
	return shares, nil
}

//nolint:dupl // false positive: duplicate but for scalars
func (d *Scheme) Open(shares ...*Share) (curves.Scalar, error) {
	if len(shares) < int(d.Threshold) {
		return nil, errs.NewSize("invalid number of shares")
	}

	dups := make(map[types.SharingID]bool, len(shares))
	xs := make([]curves.Scalar, len(shares))
	ys := make([]curves.Scalar, len(shares))

	for i, share := range shares {
		err := share.Validate(d.Curve)
		if err != nil {
			return nil, errs.WrapArgument(err, "invalid share")
		}
		if uint(share.Id) > d.Total {
			return nil, errs.NewValue("invalid share identifier id: %d must be greater than total: %d", share.Id, d.Total)
		}
		if _, in := dups[share.Id]; in {
			return nil, errs.NewMembership("duplicate share")
		}

		dups[share.Id] = true
		ys[i] = share.Value
		xs[i] = share.Id.ToScalar(d.Curve.ScalarField())
	}

	result, err := lagrange.Interpolate(d.Curve, xs, ys, d.Curve.ScalarField().Zero())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not interpolate")
	}

	return result, nil
}

//nolint:dupl // false positive: duplicate but for points
func (d *Scheme) OpenInExponent(shares ...*ShareInExp) (curves.Point, error) {
	if len(shares) < int(d.Threshold) {
		return nil, errs.NewSize("invalid number of shares")
	}

	dups := make(map[types.SharingID]bool, len(shares))
	xs := make([]curves.Scalar, len(shares))
	ys := make([]curves.Point, len(shares))

	for i, share := range shares {
		err := share.Validate(d.Curve)
		if err != nil {
			return nil, errs.WrapArgument(err, "invalid share")
		}
		if uint(share.Id) > d.Total {
			return nil, errs.NewValue("invalid share identifier id: %d must be greater than total: %d", share.Id, d.Total)
		}
		if _, in := dups[share.Id]; in {
			return nil, errs.NewMembership("duplicate share")
		}

		dups[share.Id] = true
		ys[i] = share.Value
		xs[i] = share.Id.ToScalar(d.Curve.ScalarField())
	}

	result, err := lagrange.InterpolateInTheExponent(d.Curve, xs, ys, d.Curve.ScalarField().Zero())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not interpolate")
	}

	return result, nil
}

func (*Scheme) ShareAdd(lhs, rhs *Share) *Share {
	return lhs.Add(rhs)
}

func (*Scheme) ShareAddValue(lhs *Share, rhs curves.Scalar) *Share {
	return lhs.AddValue(rhs)
}

func (*Scheme) ShareSub(lhs, rhs *Share) *Share {
	return lhs.Sub(rhs)
}

func (*Scheme) ShareSubValue(lhs *Share, rhs curves.Scalar) *Share {
	return lhs.SubValue(rhs)
}

func (*Scheme) ShareNeg(lhs *Share) *Share {
	return lhs.Neg()
}

func (*Scheme) ShareMul(lhs *Share, rhs curves.Scalar) *Share {
	return lhs.ScalarMul(rhs)
}

func (d *Scheme) GeneratePolynomialAndShares(secret curves.Scalar, prng io.Reader) (map[types.SharingID]*Share, *polynomials.Polynomial, error) {
	poly, err := polynomials.NewRandomPolynomial(secret, d.Threshold, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not generate polynomial")
	}

	shares := make(map[types.SharingID]*Share)
	for i := range d.Total {
		sharingId := types.SharingID(i + 1)
		x := sharingId.ToScalar(d.Curve.ScalarField())
		shares[sharingId] = &Share{
			Id:    sharingId,
			Value: poly.Evaluate(x),
		}
	}

	return shares, poly, nil
}

func (d *Scheme) LagrangeCoefficients(identities []types.SharingID) (map[types.SharingID]curves.Scalar, error) {
	if len(identities) < int(d.Threshold) {
		return nil, errs.NewArgument("not enough identities")
	}
	if len(identities) > int(d.Total) {
		return nil, errs.NewArgument("too many identities")
	}
	lambdas, err := LagrangeCoefficients(d.Curve.ScalarField(), identities)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute lagrange coefficients")
	}
	return lambdas, nil
}

func LagrangeCoefficients(field curves.ScalarField, sharingIds []types.SharingID) (map[types.SharingID]curves.Scalar, error) {
	if hashset.NewComparableHashSet[types.SharingID](sharingIds...).Size() != len(sharingIds) {
		return nil, errs.NewMembership("invalid sharing id hash set")
	}

	sharingIdsScalar := make([]curves.Scalar, len(sharingIds))
	for i := 0; i < len(sharingIds); i++ {
		sharingIdsScalar[i] = sharingIds[i].ToScalar(field)
	}

	basisPolynomials, err := lagrange.Basis(field, sharingIdsScalar, field.Zero()) // secret is at 0
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute all basis polynomials at x=0")
	}

	result := make(map[types.SharingID]curves.Scalar, len(basisPolynomials))
	for i, li := range basisPolynomials {
		result[sharingIds[i]] = li
	}

	return result, nil
}

func validateInputs(threshold, total uint, curve curves.Curve) error {
	if threshold > total {
		return errs.NewValue("total cannot be less than threshold")
	}
	if threshold < 2 {
		return errs.NewValue("threshold cannot be less than 2")
	}
	if curve == nil {
		return errs.NewIsNil("invalid field")
	}

	return nil
}
