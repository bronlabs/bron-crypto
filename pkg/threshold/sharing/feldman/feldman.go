package feldman

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

type Share = shamir.Share

func Verify(share *Share, commitments []curves.Point) (err error) {
	curve := share.Value.ScalarField().Curve()
	err = share.Validate(curve)
	if err != nil {
		return errs.WrapVerificationFailed(err, "share validation failed")
	}
	x := curve.ScalarField().New(uint64(share.Id))
	i := curve.ScalarField().One()

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

	lhs := commitments[0].Curve().Generator().Mul(share.Value)
	if lhs.Equal(rhs) {
		return nil
	} else {
		return errs.NewVerificationFailed("not equal")
	}
}

type Dealer struct {
	Threshold, Total int
	Curve            curves.Curve

	_ types.Incomparable
}

func NewDealer(threshold, total int, curve curves.Curve) (*Dealer, error) {
	dealer := &Dealer{Threshold: threshold, Total: total, Curve: curve}
	if err := dealer.Validate(); err != nil {
		return nil, errs.WrapFailed(err, "invalid dealer")
	}
	return dealer, nil
}

func (f *Dealer) Split(secret curves.Scalar, prng io.Reader) (commitments []curves.Point, shares []*Share, err error) {
	shamirDealer := &shamir.Dealer{
		Threshold: f.Threshold,
		Total:     f.Total,
		Curve:     f.Curve,
	}
	shares, poly, err := shamirDealer.GeneratePolynomialAndShares(secret, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not generate polynomial and shares")
	}
	commitments = make([]curves.Point, f.Threshold)
	for i := range commitments {
		commitments[i] = f.Curve.ScalarBaseMult(poly.Coefficients[i])
	}
	return commitments, shares, nil
}

func (f *Dealer) LagrangeCoeffs(shares map[int]*Share) (map[int]curves.Scalar, error) {
	shamirDealer := &shamir.Dealer{
		Threshold: f.Threshold,
		Total:     f.Total,
		Curve:     f.Curve,
	}
	identities := make([]int, len(shares))
	for i, xi := range shares {
		identities[i] = xi.Id
	}
	lambdas, err := shamirDealer.LagrangeCoefficients(identities)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive lagrange coefficients")
	}
	return lambdas, nil
}

func (f *Dealer) Combine(shares ...*Share) (curves.Scalar, error) {
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

func (f *Dealer) CombinePoints(shares ...*Share) (curves.Point, error) {
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

func (f *Dealer) Validate() error {
	if f.Total < f.Threshold {
		return errs.NewInvalidArgument("total cannot be less than threshold")
	}
	if f.Threshold < 2 {
		return errs.NewInvalidArgument("threshold cannot be less than 2")
	}
	if f.Curve == nil {
		return errs.NewIsNil("curve is nil")
	}
	return nil
}
