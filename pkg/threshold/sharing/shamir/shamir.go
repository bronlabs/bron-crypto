package shamir

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/polynomials"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type Share struct {
	Id    int           `json:"identifier"`
	Value curves.Scalar `json:"value"`

	_ types.Incomparable
}

// Validate checks if the share is valid (non-zero value, non-zero id and in the correct curve).
func (ss Share) Validate(curve curves.Curve) error {
	if ss.Id == 0 {
		return errs.NewInvalidIdentifier("invalid identifier - id is zero")
	}
	if ss.Value.IsZero() {
		return errs.NewIsZero("invalid share - value is zero")
	}
	shareCurve := ss.Value.Curve()
	if shareCurve.Name() != curve.Name() {
		return errs.NewInvalidCurve("curve mismatch %s != %s", shareCurve.Name(), curve.Name())
	}

	return nil
}

func (ss Share) LagrangeCoefficient(identities []int) (curves.Scalar, error) {
	curve := ss.Value.Curve()
	coefficients, err := LagrangeCoefficients(curve, identities)
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
	Curve            curves.Curve

	_ types.Incomparable
}

func NewDealer(threshold, total int, curve curves.Curve) (*Dealer, error) {
	err := validateInputs(threshold, total, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to validate inputs")
	}

	return &Dealer{Threshold: threshold, Total: total, Curve: curve}, nil
}

func validateInputs(threshold, total int, curve curves.Curve) error {
	if total < threshold {
		return errs.NewIncorrectCount("total cannot be less than threshold")
	}
	if threshold < 2 {
		return errs.NewIncorrectCount("threshold cannot be less than 2")
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
		x := s.Curve.Scalar().New(uint64(i + 1))
		shares[i] = &Share{
			Id:    i + 1,
			Value: poly.Evaluate(x),
		}
	}
	return shares, poly, nil
}

func (s *Dealer) LagrangeCoefficients(identities []int) (map[int]curves.Scalar, error) {
	if len(identities) < s.Threshold {
		return nil, errs.NewInvalidArgument("not enough identities")
	}
	if len(identities) > s.Total {
		return nil, errs.NewInvalidArgument("too many identities")
	}
	lambdas, err := LagrangeCoefficients(s.Curve, identities)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not ocmpute lagrange coefficients")
	}
	return lambdas, nil
}

func (s *Dealer) Combine(shares ...*Share) (curves.Scalar, error) {
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
		xs[i] = s.Curve.Scalar().New(uint64(share.Id))
	}
	return s.interpolate(xs, ys, s.Curve.Scalar().Zero())
}

func (s *Dealer) CombinePoints(shares ...*Share) (curves.Point, error) {
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
		xs[i] = s.Curve.Scalar().New(uint64(share.Id))
	}
	return s.interpolatePoint(xs, ys, s.Curve.Scalar().Zero())
}

func (s *Dealer) interpolate(xs, ys []curves.Scalar, evaluateAt curves.Scalar) (curves.Scalar, error) {
	result, err := polynomials.Interpolate(s.Curve, xs, ys, evaluateAt)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not interpolate")
	}
	return result, nil
}

func (s *Dealer) interpolatePoint(xs []curves.Scalar, ys []curves.Point, evaluateAt curves.Scalar) (curves.Point, error) {
	result, err := polynomials.InterpolateInTheExponent(s.Curve, xs, ys, evaluateAt)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not interpolate in the exponent")
	}
	return result, nil
}

func LagrangeCoefficients(curve curves.Curve, sharingIds []int) (map[int]curves.Scalar, error) {
	sharingIdsScalar := make([]curves.Scalar, len(sharingIds))
	for i := 0; i < len(sharingIds); i++ {
		sharingIdsScalar[i] = curve.Scalar().New(uint64(sharingIds[i]))
	}
	basisPolynomials, err := polynomials.LagrangeBasis(curve, sharingIdsScalar, curve.Scalar().Zero()) // secret is at 0
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute all basis polynomialsa at x=0")
	}
	result := make(map[int]curves.Scalar, len(basisPolynomials))
	for i, li := range basisPolynomials {
		result[sharingIds[i]] = li
	}
	return result, nil
}
