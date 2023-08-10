package shamir

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/sharing"
)

type Share struct {
	Id    int           `json:"identifier"`
	Value curves.Scalar `json:"value"`
}

func (ss Share) Validate(curve *curves.Curve) error {
	if ss.Id == 0 {
		return errs.NewInvalidIdentifier("invalid identifier - id is zero")
	}
	if ss.Value.IsZero() {
		return errs.NewIsZero("invalid share - value is zero")
	}
	if shareCurveName := ss.Value.CurveName(); shareCurveName != curve.Name {
		return errs.NewInvalidCurve("curve mismatch %s != %s", shareCurveName, curve.Name)
	}

	return nil
}

func (ss Share) LagrangeCoefficient(identities []int) (curves.Scalar, error) {
	curve, err := curves.GetCurveByName(ss.Value.CurveName())
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "could not fetch curve by name")
	}
	coefficients, err := sharing.LagrangeCoefficients(curve, identities)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive lagrange coefficients")
	}
	return coefficients[ss.Id], nil
}

func (ss Share) ToAdditive(identities []int) (curves.Scalar, error) {
	lambda, err := ss.LagrangeCoefficient(identities)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive my lagrange coefficient")
	}
	return lambda.Mul(ss.Value), nil
}

type Dealer struct {
	Threshold, Total int
	Curve            *curves.Curve
}

func NewDealer(threshold, total int, curve *curves.Curve) (*Dealer, error) {
	if total < threshold {
		return nil, errs.NewInvalidArgument("total cannot be less than threshold")
	}
	if threshold < 2 {
		return nil, errs.NewInvalidArgument("threshold cannot be less than 2")
	}
	if curve == nil {
		return nil, errs.NewIsNil("invalid curve")
	}
	return &Dealer{threshold, total, curve}, nil
}

func (s Dealer) Split(secret curves.Scalar, prng io.Reader) ([]*Share, error) {
	if secret.IsZero() {
		return nil, errs.NewIsZero("invalid secret")
	}
	shares, _ := s.GeneratePolynomialAndShares(secret, prng)
	return shares, nil
}

func (s Dealer) GeneratePolynomialAndShares(secret curves.Scalar, prng io.Reader) ([]*Share, *sharing.Polynomial) {
	poly := new(sharing.Polynomial).NewPolynomial(secret, s.Threshold, prng)
	shares := make([]*Share, s.Total)
	for i := range shares {
		x := s.Curve.Scalar.New(i + 1)
		shares[i] = &Share{
			Id:    i + 1,
			Value: poly.Evaluate(x),
		}
	}
	return shares, poly
}

func (s Dealer) LagrangeCoefficients(identities []int) (map[int]curves.Scalar, error) {
	if len(identities) < s.Threshold {
		return nil, errs.NewInvalidArgument("not enough identities")
	}
	if len(identities) > s.Total {
		return nil, errs.NewInvalidArgument("too many identities")
	}
	lambdas, err := sharing.LagrangeCoefficients(s.Curve, identities)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not ocmpute lagrange coefficients")
	}
	return lambdas, nil
}

func (s Dealer) Combine(shares ...*Share) (curves.Scalar, error) {
	if len(shares) < s.Threshold {
		return nil, errs.NewIncorrectCount("invalid number of shares")
	}
	dups := make(map[int]bool, len(shares))
	xs := make([]curves.Scalar, len(shares))
	ys := make([]curves.Scalar, len(shares))

	for i, share := range shares {
		err := share.Validate(s.Curve)
		if err != nil {
			return nil, errs.WrapInvalidArgument(err, "invalid share")
		}
		if share.Id > s.Total {
			return nil, errs.NewInvalidIdentifier("invalid share identifier id: %d must be greater than total: %d", share.Id, s.Total)
		}
		if _, in := dups[share.Id]; in {
			return nil, errs.NewDuplicate("duplicate share")
		}
		dups[share.Id] = true
		ys[i] = share.Value
		xs[i] = s.Curve.Scalar.New(share.Id)
	}
	return s.interpolate(xs, ys, s.Curve.Scalar.Zero())
}

func (s Dealer) CombinePoints(shares ...*Share) (curves.Point, error) {
	if len(shares) < s.Threshold {
		return nil, errs.NewIncorrectCount("invalid number of shares (%d != %d)", len(shares), s.Threshold)
	}

	dups := make(map[int]bool, len(shares))
	xs := make([]curves.Scalar, len(shares))
	ys := make([]curves.Point, len(shares))

	for i, share := range shares {
		err := share.Validate(s.Curve)
		if err != nil {
			return nil, errs.WrapInvalidArgument(err, "invalid share")
		}
		if share.Id > s.Total {
			return nil, errs.NewInvalidIdentifier("invalid share id: %d must be greater than total: %d", share.Id, s.Total)
		}
		if _, in := dups[share.Id]; in {
			return nil, errs.NewDuplicate("duplicate share")
		}
		dups[share.Id] = true
		ys[i] = s.Curve.ScalarBaseMult(share.Value)
		xs[i] = s.Curve.Scalar.New(share.Id)
	}
	return s.interpolatePoint(xs, ys, s.Curve.Scalar.Zero())
}

func (s Dealer) interpolate(xs, ys []curves.Scalar, evaluateAt curves.Scalar) (curves.Scalar, error) {
	result, err := sharing.Interpolate(s.Curve, xs, ys, evaluateAt)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not interpolate")
	}
	return result, nil
}

func (s Dealer) interpolatePoint(xs []curves.Scalar, ys []curves.Point, evaluateAt curves.Scalar) (curves.Point, error) {
	result, err := sharing.InterpolateInTheExponent(s.Curve, xs, ys, evaluateAt)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not interpolate in the exponent")
	}
	return result, nil
}
