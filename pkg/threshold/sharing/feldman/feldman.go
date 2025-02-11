package feldman_vss

import (
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/polynomials"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/shamir"
)

var (
	_ sharing.LinearVerifiableScheme[*Share, curves.Scalar, curves.Scalar, []curves.Point] = (*Scheme)(nil)
)

type Share = shamir.Share

type Scheme struct {
	Threshold, Total uint
	Curve            curves.Curve

	_ ds.Incomparable
}

func NewScheme(threshold, total uint, curve curves.Curve) (*Scheme, error) {
	dealer := &Scheme{
		Threshold: threshold, Total: total, Curve: curve,
	}
	if err := dealer.Validate(); err != nil {
		return nil, errs.WrapFailed(err, "invalid dealer")
	}

	return dealer, nil
}

func (d *Scheme) DealPolynomial(coefficients []curves.Scalar) (shares map[types.SharingID]*Share, verificationVector []curves.Point, err error) {
	if len(coefficients) != int(d.Threshold) {
		return nil, nil, errs.NewValidation("invalid coefficients length")
	}

	polynomial := polynomials.NewPolynomial(coefficients)
	shares = make(map[types.SharingID]*shamir.Share)
	for i := range d.Total {
		sharingId := types.SharingID(i + 1)
		x := sharingId.ToScalar(d.Curve.ScalarField())
		shares[sharingId] = &shamir.Share{
			Id:    sharingId,
			Value: polynomial.Evaluate(x),
		}
	}

	verificationVector = make([]curves.Point, len(polynomial.Coefficients))
	for i, c := range polynomial.Coefficients {
		verificationVector[i] = d.Curve.ScalarBaseMult(c)
	}

	return shares, verificationVector, nil
}

func (d *Scheme) DealVerifiable(secret curves.Scalar, prng io.Reader) (shares map[types.SharingID]*Share, verificationVector []curves.Point, err error) {
	shamirDealer, err := shamir.NewScheme(d.Threshold, d.Total, d.Curve)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not generate polynomial and shares")
	}
	_, poly, err := shamirDealer.GeneratePolynomialAndShares(secret, prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not generate polynomial and shares")
	}

	shares, verificationVector, err = d.DealPolynomial(poly.Coefficients)
	return shares, verificationVector, err
}

func (d *Scheme) Deal(secret curves.Scalar, prng io.Reader) (shares map[types.SharingID]*Share, err error) {
	shares, _, err = d.DealVerifiable(secret, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not deal shares")
	}

	return shares, nil
}

func (d *Scheme) Open(shares ...*Share) (curves.Scalar, error) {
	shamirDealer, err := shamir.NewScheme(d.Threshold, d.Total, d.Curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not combine shares")
	}

	result, err := shamirDealer.Open(shares...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not combine shares")
	}
	return result, nil
}

func (d *Scheme) VerifyShare(share *Share, verificationVector []curves.Point) (err error) {
	if len(verificationVector) != int(d.Threshold) {
		return errs.NewFailed("invalid commitment vector")
	}
	if share.SharingId() < 1 || uint(share.SharingId()) > d.Total {
		return errs.NewFailed("invalid sharing id")
	}

	x := share.Id.ToScalar(d.Curve.ScalarField())
	y := polynomials.EvalInExponent(verificationVector, x)
	if !y.Equal(d.Curve.ScalarBaseMult(share.Value)) {
		return errs.NewFailed("invalid share")
	}

	return nil
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

func (*Scheme) VerificationAdd(lhs, rhs []curves.Point) []curves.Point {
	out := make([]curves.Point, len(lhs))
	for i, l := range lhs {
		r := rhs[i]
		out[i] = l.Add(r)
	}
	return out
}

func (d *Scheme) VerificationAddValue(lhs []curves.Point, rhs curves.Scalar) []curves.Point {
	r := d.Curve.ScalarBaseMult(rhs)
	out := make([]curves.Point, len(lhs))
	for i, l := range lhs {
		if i == 0 {
			out[i] = l.Add(r)
		} else {
			out[i] = l
		}
	}
	return out
}

func (*Scheme) VerificationSub(lhs, rhs []curves.Point) []curves.Point {
	out := make([]curves.Point, len(lhs))
	for i, l := range lhs {
		r := rhs[i]
		out[i] = l.Sub(r)
	}
	return out
}

func (d *Scheme) VerificationSubValue(lhs []curves.Point, rhs curves.Scalar) []curves.Point {
	r := d.Curve.ScalarBaseMult(rhs)
	out := make([]curves.Point, len(lhs))
	for i, l := range lhs {
		if i == 0 {
			out[i] = l.Sub(r)
		} else {
			out[i] = l
		}
	}
	return out
}

func (*Scheme) VerificationNeg(lhs []curves.Point) []curves.Point {
	out := make([]curves.Point, len(lhs))
	for i, l := range lhs {
		out[i] = l.Neg()
	}
	return out
}

func (*Scheme) VerificationMul(lhs []curves.Point, rhs curves.Scalar) []curves.Point {
	out := make([]curves.Point, len(lhs))
	for i, l := range lhs {
		out[i] = l.ScalarMul(rhs)
	}
	return out
}

func (d *Scheme) Validate() error {
	if d == nil {
		return errs.NewIsNil("receiver")
	}
	if d.Total < d.Threshold {
		return errs.NewArgument("total cannot be less than threshold")
	}
	if d.Threshold < 2 {
		return errs.NewArgument("threshold cannot be less than 2")
	}
	if d.Curve == nil {
		return errs.NewIsNil("curve is nil")
	}
	return nil
}
