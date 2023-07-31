package feldman

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/shamir"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
)

type Share = shamir.Share

func Verify(share *Share, commitments []curves.Point) (err error) {
	curve, err := curves.GetCurveByName(commitments[0].CurveName())
	if err != nil {
		return errs.WrapInvalidCurve(err, "no such curve: %s", commitments[0].CurveName())
	}
	err = share.Validate(curve)
	if err != nil {
		return errs.WrapVerificationFailed(err, "share validation failed")
	}
	x := curve.Scalar.New(share.Id)
	i := curve.Scalar.One()

	rhs := commitments[0].Identity()
	is := make([]curves.Scalar, len(commitments)-1)
	for j := 1; j < len(commitments); j++ {
		i = i.Mul(x)
		is[j-1] = i
	}
	rhs, err = rhs.MultiScalarMult(is, commitments[1:])
	if err != nil {
		return errs.WrapVerificationFailed(err, "multiscalarmult failed")
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
		return nil, errs.NewIsNil("curve is nil")
	}

	return &Dealer{threshold, total, curve}, nil
}

func (f Dealer) Split(secret curves.Scalar, prng io.Reader) (commitments []curves.Point, shares []*Share, err error) {
	if secret.IsZero() {
		return nil, nil, errs.NewIsZero("secret is nil")
	}
	shamir := &shamir.Dealer{
		Threshold: f.Threshold,
		Total:     f.Total,
		Curve:     f.Curve,
	}
	shares, poly := shamir.GeneratePolynomialAndShares(secret, prng)
	commitments = make([]curves.Point, f.Threshold)
	for i := range commitments {
		commitments[i] = f.Curve.ScalarBaseMult(poly.Coefficients[i])
	}
	return commitments, shares, nil
}

func (f Dealer) LagrangeCoeffs(shares map[int]*Share) (map[int]curves.Scalar, error) {
	shamir := &shamir.Dealer{
		Threshold: f.Threshold,
		Total:     f.Total,
		Curve:     f.Curve,
	}
	identities := make([]int, 0)
	for _, xi := range shares {
		identities = append(identities, xi.Id)
	}
	return shamir.LagrangeCoefficients(identities)
}

func (f Dealer) Combine(shares ...*Share) (curves.Scalar, error) {
	shamir := &shamir.Dealer{
		Threshold: f.Threshold,
		Total:     f.Total,
		Curve:     f.Curve,
	}
	return shamir.Combine(shares...)
}

func (f Dealer) CombinePoints(shares ...*Share) (curves.Point, error) {
	shamir := &shamir.Dealer{
		Threshold: f.Threshold,
		Total:     f.Total,
		Curve:     f.Curve,
	}
	return shamir.CombinePoints(shares...)
}
