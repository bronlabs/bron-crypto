package shamir

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/polynomials"
	"github.com/copperexchange/krypton-primitives/pkg/base/polynomials/interpolation/lagrange"
)

type Share struct {
	Id    uint          `json:"identifier"`
	Value curves.Scalar `json:"value"`

	_ ds.Incomparable
}

// TODO: pointer receiver
// TODO: add transform from t-n1 to t-n2
func (ss Share) Validate(curve curves.Curve) error {
	if ss.Id == 0 {
		return errs.NewIdentifier("invalid identifier - id is zero")
	}
	if ss.Value.IsZero() {
		return errs.NewIsZero("invalid share - value is zero")
	}
	shareCurve := ss.Value.ScalarField().Curve()
	if shareCurve.Name() != curve.Name() {
		return errs.NewCurve("curve mismatch %s != %s", shareCurve.Name(), curve.Name())
	}

	return nil
}

func (ss Share) LagrangeCoefficient(identities []uint) (curves.Scalar, error) {
	curve := ss.Value.ScalarField().Curve()
	coefficients, err := LagrangeCoefficients(curve, identities)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive lagrange coefficients")
	}
	return coefficients[ss.Id], nil
}

func (ss Share) ToAdditive(identities []uint) (curves.Scalar, error) {
	lambda, err := ss.LagrangeCoefficient(identities)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive my lagrange coefficient")
	}
	return lambda.Mul(ss.Value), nil
}

type Dealer struct {
	Threshold, Total uint
	Curve            curves.Curve

	_ ds.Incomparable
}

func NewDealer(threshold, total uint, curve curves.Curve) (*Dealer, error) {
	err := validateInputs(threshold, total, curve)
	if err != nil {
		return nil, errs.WrapArgument(err, "failed to validate inputs")
	}

	return &Dealer{Threshold: threshold, Total: total, Curve: curve}, nil
}

func validateInputs(threshold, total uint, curve curves.Curve) error {
	if total < threshold {
		return errs.NewValue("total cannot be less than threshold")
	}
	if threshold < 2 {
		return errs.NewValue("threshold cannot be less than 2")
	}
	if curve == nil {
		return errs.NewIsNil("invalid curve")
	}
	return nil
}

func (s *Dealer) Split(secret curves.Scalar, prng io.Reader) ([]*Share, error) {
	if secret == nil {
		return nil, errs.NewIsNil("secret is nil")
	}
	shares, _, err := s.GeneratePolynomialAndShares(secret, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate polynomial and shares")
	}
	return shares, nil
}

func (s *Dealer) GeneratePolynomialAndShares(secret curves.Scalar, prng io.Reader) ([]*Share, *polynomials.Polynomial, error) {
	poly, err := polynomials.NewRandomPolynomial(secret, s.Threshold, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not generate polynomial")
	}
	shares := make([]*Share, s.Total)
	for i := range shares {
		x := s.Curve.ScalarField().New(uint64(i + 1))
		shares[i] = &Share{
			Id:    uint(i + 1),
			Value: poly.Evaluate(x),
		}
	}
	return shares, poly, nil
}

func (s *Dealer) LagrangeCoefficients(identities []uint) (map[uint]curves.Scalar, error) {
	if len(identities) < int(s.Threshold) {
		return nil, errs.NewArgument("not enough identities")
	}
	if len(identities) > int(s.Total) {
		return nil, errs.NewArgument("too many identities")
	}
	lambdas, err := LagrangeCoefficients(s.Curve, identities)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not ocmpute lagrange coefficients")
	}
	return lambdas, nil
}

func (s *Dealer) Combine(shares ...*Share) (curves.Scalar, error) {
	if len(shares) < int(s.Threshold) {
		return nil, errs.NewCount("invalid number of shares")
	}
	dups := make(map[uint]bool, len(shares))
	xs := make([]curves.Scalar, len(shares))
	ys := make([]curves.Scalar, len(shares))

	for i, share := range shares {
		err := share.Validate(s.Curve)
		if err != nil {
			return nil, errs.WrapArgument(err, "invalid share")
		}
		if share.Id > s.Total {
			return nil, errs.NewIdentifier("invalid share identifier id: %d must be greater than total: %d", share.Id, s.Total)
		}
		if _, in := dups[share.Id]; in {
			return nil, errs.NewDuplicate("duplicate share")
		}
		dups[share.Id] = true
		ys[i] = share.Value
		xs[i] = s.Curve.ScalarField().New(uint64(share.Id))
	}
	result, err := lagrange.Interpolate(s.Curve, xs, ys, s.Curve.ScalarField().Zero())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not interpolate")
	}
	return result, nil
}

func (s *Dealer) CombinePoints(shares ...*Share) (curves.Point, error) {
	if len(shares) < int(s.Threshold) {
		return nil, errs.NewCount("invalid number of shares (%d != %d)", len(shares), s.Threshold)
	}

	dups := make(map[uint]bool, len(shares))
	xs := make([]curves.Scalar, len(shares))
	ys := make([]curves.Point, len(shares))

	for i, share := range shares {
		err := share.Validate(s.Curve)
		if err != nil {
			return nil, errs.WrapArgument(err, "invalid share")
		}
		if share.Id > s.Total {
			return nil, errs.NewIdentifier("invalid share id: %d must be greater than total: %d", share.Id, s.Total)
		}
		if _, in := dups[share.Id]; in {
			return nil, errs.NewDuplicate("duplicate share")
		}
		dups[share.Id] = true
		ys[i] = s.Curve.ScalarBaseMult(share.Value)
		xs[i] = s.Curve.ScalarField().New(uint64(share.Id))
	}
	result, err := lagrange.InterpolateInTheExponent(s.Curve, xs, ys, s.Curve.ScalarField().Zero())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not interpolate in the exponent")
	}
	return result, nil
}

func LagrangeCoefficients(curve curves.Curve, sharingIds []uint) (map[uint]curves.Scalar, error) {
	if hashset.NewComparableHashSet[uint](sharingIds...).Size() != len(sharingIds) {
		return nil, errs.NewMembership("invalid sharing id hash set")
	}
	sharingIdsScalar := make([]curves.Scalar, len(sharingIds))
	for i := 0; i < len(sharingIds); i++ {
		sharingIdsScalar[i] = curve.ScalarField().New(uint64(sharingIds[i]))
	}
	basisPolynomials, err := lagrange.Basis(curve, sharingIdsScalar, curve.ScalarField().Zero()) // secret is at 0
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute all basis polynomialsa at x=0")
	}
	result := make(map[uint]curves.Scalar, len(basisPolynomials))
	for i, li := range basisPolynomials {
		result[sharingIds[i]] = li
	}
	return result, nil
}
