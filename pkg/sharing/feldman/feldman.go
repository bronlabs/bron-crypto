package feldman

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/sharing/shamir"
)

type Share = shamir.Share

func Verify(share *Share, commitments []curves.Point) (err error) {
	curve, err := share.Value.Curve()
	if err != nil {
		return errs.WrapInvalidCurve(err, "no such curve: %s", curve.Name())
	}
	err = share.Validate(curve)
	if err != nil {
		return errs.WrapVerificationFailed(err, "share validation failed")
	}
	x := curve.Scalar().New(share.Id)
	i := curve.Scalar().One()

	is := make([]curves.Scalar, len(commitments))
	for j := 1; j < len(commitments); j++ {
		i = i.Mul(x)
		is[j] = i
	}
	rhs, err := curve.MultiScalarMult(is[1:], commitments[1:])
	if err != nil {
		return errs.WrapFailed(err, "multiscalarmult failed")
	}
	rhs = rhs.Add(commitments[0])

	lhs := commitments[0].Generator().Mul(share.Value)
	if lhs.Equal(rhs) {
		return nil
	} else {
		return errs.NewVerificationFailed("not equal")
	}
}

type Dealer struct {
	Threshold, Total int
	Curve            curves.Curve

	_ helper_types.Incomparable
}

func NewDealer(threshold, total int, curve curves.Curve) (*Dealer, error) {
	if total < threshold {
		return nil, errs.NewInvalidArgument("total cannot be less than threshold")
	}
	if threshold < 2 {
		return nil, errs.NewInvalidArgument("threshold cannot be less than 2")
	}
	if curve == nil {
		return nil, errs.NewIsNil("curve is nil")
	}

	return &Dealer{Threshold: threshold, Total: total, Curve: curve}, nil
}

func (f Dealer) Split(secret curves.Scalar, prng io.Reader) (commitments []curves.Point, shares []*Share, err error) {
	if secret.IsZero() {
		return nil, nil, errs.NewIsZero("secret is nil")
	}
	shamirDealer := &shamir.Dealer{
		Threshold: f.Threshold,
		Total:     f.Total,
		Curve:     f.Curve,
	}
	shares, poly := shamirDealer.GeneratePolynomialAndShares(secret, prng)
	commitments = make([]curves.Point, f.Threshold)
	for i := range commitments {
		commitments[i] = f.Curve.ScalarBaseMult(poly.Coefficients[i])
	}
	return commitments, shares, nil
}

func (f Dealer) LagrangeCoeffs(shares map[int]*Share) (map[int]curves.Scalar, error) {
	shamirDealer := &shamir.Dealer{
		Threshold: f.Threshold,
		Total:     f.Total,
		Curve:     f.Curve,
	}
	identities := make([]int, 0)
	for _, xi := range shares {
		identities = append(identities, xi.Id)
	}
	lambdas, err := shamirDealer.LagrangeCoefficients(identities)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive lagrange coefficients")
	}
	return lambdas, nil
}

func (f Dealer) Combine(shares ...*Share) (curves.Scalar, error) {
	shamirDealer := &shamir.Dealer{
		Threshold: f.Threshold,
		Total:     f.Total,
		Curve:     f.Curve,
	}
	result, err := shamirDealer.Combine(shares...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not combine shares")
	}
	return result, nil
}

func (f Dealer) CombinePoints(shares ...*Share) (curves.Point, error) {
	shamirDealer := &shamir.Dealer{
		Threshold: f.Threshold,
		Total:     f.Total,
		Curve:     f.Curve,
	}
	result, err := shamirDealer.CombinePoints(shares...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not combine points")
	}
	return result, nil
}
