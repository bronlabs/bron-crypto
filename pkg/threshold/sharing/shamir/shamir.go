package shamir

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation/lagrange"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
)

type Scheme[SF fields.PrimeField[S], S fields.PrimeFieldElement[S]] struct {
	Threshold   uint
	Total       uint
	ScalarField SF
}

func NewScheme[SF fields.PrimeField[S], S fields.PrimeFieldElement[S]](threshold, total uint, field SF) (*Scheme[SF, S], error) {
	err := validateInputs(threshold, total)
	if err != nil {
		return nil, errs.WrapArgument(err, "failed to validate inputs")
	}

	return &Scheme[SF, S]{
		Threshold:   threshold,
		Total:       total,
		ScalarField: field,
	}, nil
}

func (d *Scheme[SF, S]) Deal(secret S, prng io.Reader) (map[types.SharingID]*Share[S], error) {
	// TODO: how?
	//if secret == nil {
	//	return nil, errs.NewIsNil("secret is nil")
	//}

	shares, _, err := d.GeneratePolynomialAndShares(secret, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate polynomial and shares")
	}
	return shares, nil
}

//nolint:dupl // false positive: duplicate but for scalars
func (d *Scheme[SF, S]) Open(shares ...*Share[S]) (S, error) {
	var nilS S

	if len(shares) < int(d.Threshold) {
		return nilS, errs.NewSize("invalid number of shares")
	}

	dups := make(map[types.SharingID]bool, len(shares))
	xs := make([]S, len(shares))
	ys := make([]S, len(shares))

	for i, share := range shares {
		//err := share.Validate(d.Curve)
		//if err != nil {
		//	return nil, errs.WrapArgument(err, "invalid share")
		//}
		if uint(share.Id) > d.Total {
			return nilS, errs.NewValue("invalid share identifier id: %d must be greater than total: %d", share.Id, d.Total)
		}
		if _, in := dups[share.Id]; in {
			return nilS, errs.NewMembership("duplicate share")
		}

		dups[share.Id] = true
		ys[i] = share.Value
		xs[i] = types.SharingIDToScalar(share.Id, d.ScalarField)
	}

	result, err := lagrange.Interpolate(xs, ys, d.ScalarField.Zero())
	if err != nil {
		return nilS, errs.WrapFailed(err, "could not interpolate")
	}

	return result, nil
}

////nolint:dupl // false positive: duplicate but for points
//func (d *Scheme) OpenInExponent(shares ...*ShareInExp) (curves.Point, error) {
//	if len(shares) < int(d.Threshold) {
//		return nil, errs.NewSize("invalid number of shares")
//	}
//
//	dups := make(map[types.SharingID]bool, len(shares))
//	xs := make([]curves.Scalar, len(shares))
//	ys := make([]curves.Point, len(shares))
//
//	for i, share := range shares {
//		err := share.Validate(d.Curve)
//		if err != nil {
//			return nil, errs.WrapArgument(err, "invalid share")
//		}
//		if uint(share.Id) > d.Total {
//			return nil, errs.NewValue("invalid share identifier id: %d must be greater than total: %d", share.Id, d.Total)
//		}
//		if _, in := dups[share.Id]; in {
//			return nil, errs.NewMembership("duplicate share")
//		}
//
//		dups[share.Id] = true
//		ys[i] = share.Value
//		xs[i] = share.Id.ToScalar(d.Curve.ScalarField())
//	}
//
//	result, err := lagrange.InterpolateInTheExponent(d.Curve, xs, ys, d.Curve.ScalarField().Zero())
//	if err != nil {
//		return nil, errs.WrapFailed(err, "could not interpolate")
//	}
//
//	return result, nil
//}

func (*Scheme[SF, S]) ShareAdd(lhs, rhs *Share[S]) *Share[S] {
	return lhs.Add(rhs)
}

func (*Scheme[SF, S]) ShareAddValue(lhs *Share[S], rhs S) *Share[S] {
	return lhs.AddValue(rhs)
}

func (*Scheme[SF, S]) ShareSub(lhs, rhs *Share[S]) *Share[S] {
	return lhs.Sub(rhs)
}

func (*Scheme[SF, S]) ShareSubValue(lhs *Share[S], rhs S) *Share[S] {
	return lhs.SubValue(rhs)
}

func (*Scheme[SF, S]) ShareNeg(lhs *Share[S]) *Share[S] {
	return lhs.Neg()
}

func (*Scheme[SF, S]) ShareMul(lhs *Share[S], rhs S) *Share[S] {
	return lhs.ScalarMul(rhs)
}

func (d *Scheme[SF, S]) GeneratePolynomialAndShares(secret S, prng io.Reader) (map[types.SharingID]*Share[S], *polynomials.Polynomial[S], error) {
	poly, err := polynomials.NewRandomPolynomial(secret, d.Threshold, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not generate polynomial")
	}

	shares := make(map[types.SharingID]*Share[S])
	for i := range d.Total {
		sharingId := types.SharingID(i + 1)
		x := types.SharingIDToScalar(sharingId, d.ScalarField)
		shares[sharingId] = &Share[S]{
			Id:    sharingId,
			Value: poly.Evaluate(x),
		}
	}

	return shares, poly, nil
}

func (d *Scheme[SF, S]) LagrangeCoefficients(identities []types.SharingID) (map[types.SharingID]S, error) {
	if len(identities) < int(d.Threshold) {
		return nil, errs.NewArgument("not enough identities")
	}
	if len(identities) > int(d.Total) {
		return nil, errs.NewArgument("too many identities")
	}
	lambdas, err := LagrangeCoefficients(d.ScalarField, identities)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute lagrange coefficients")
	}
	return lambdas, nil
}

func LagrangeCoefficients[SF fields.PrimeField[S], S fields.PrimeFieldElement[S]](field SF, sharingIds []types.SharingID) (map[types.SharingID]S, error) {
	if hashset.NewComparableHashSet[types.SharingID](sharingIds...).Size() != len(sharingIds) {
		return nil, errs.NewMembership("invalid sharing id hash set")
	}

	sharingIdsScalar := make([]S, len(sharingIds))
	for i := 0; i < len(sharingIds); i++ {
		sharingIdsScalar[i] = types.SharingIDToScalar(sharingIds[i], field)
	}

	basisPolynomials, err := lagrange.Basis(sharingIdsScalar, field.Zero()) // secret is at 0
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute all basis polynomials at x=0")
	}

	result := make(map[types.SharingID]S, len(basisPolynomials))
	for i, li := range basisPolynomials {
		result[sharingIds[i]] = li
	}

	return result, nil
}

func validateInputs(threshold, total uint) error {
	if threshold > total {
		return errs.NewValue("total cannot be less than threshold")
	}
	if threshold < 2 {
		return errs.NewValue("threshold cannot be less than 2")
	}

	//// TODO: how?
	//if curve == nil {
	//	return errs.NewIsNil("invalid field")
	//}

	return nil
}
