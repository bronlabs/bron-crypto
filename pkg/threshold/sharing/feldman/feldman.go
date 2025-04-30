package feldman_vss

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

//var (
//	_ sharing.LinearVerifiableScheme[*Share, curves.Scalar, curves.Scalar, []curves.Point] = (*Scheme)(nil)
//)

type Share[S fields.PrimeFieldElement[S]] = shamir.Share[S]

type Scheme[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] struct {
	Threshold, Total uint
	Curve            C

	_ ds.Incomparable
}

func NewScheme[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](threshold, total uint, curve C) (*Scheme[C, P, F, S], error) {
	dealer := &Scheme[C, P, F, S]{
		Threshold: threshold, Total: total, Curve: curve,
	}
	if err := dealer.Validate(); err != nil {
		return nil, errs.WrapFailed(err, "invalid dealer")
	}

	return dealer, nil
}

func (d *Scheme[C, P, F, S]) DealPolynomial(coefficients []S) (shares map[types.SharingID]*Share[S], verificationVector []P, err error) {
	if len(coefficients) != int(d.Threshold) {
		return nil, nil, errs.NewValidation("invalid coefficients length")
	}

	field := d.Curve.ScalarField()
	polynomial := polynomials.NewPolynomial(coefficients)
	shares = make(map[types.SharingID]*Share[S])
	for i := range d.Total {
		sharingId := types.SharingID(i + 1)
		x := types.SharingIDToScalar(sharingId, field)
		shares[sharingId] = &Share[S]{
			Id:    sharingId,
			Value: polynomial.Evaluate(x),
		}
	}

	verificationVector = make([]P, len(polynomial.Coefficients))
	for i, c := range polynomial.Coefficients {
		verificationVector[i] = d.Curve.Generator().ScalarMul(c)
	}

	return shares, verificationVector, nil
}

func (d *Scheme[C, P, F, S]) DealVerifiable(secret S, prng io.Reader) (shares map[types.SharingID]*Share[S], verificationVector []P, err error) {
	shamirDealer, err := shamir.NewScheme(d.Threshold, d.Total, d.Curve.ScalarField())
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

func (d *Scheme[C, P, F, S]) Deal(secret S, prng io.Reader) (shares map[types.SharingID]*Share[S], err error) {
	shares, _, err = d.DealVerifiable(secret, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not deal shares")
	}

	return shares, nil
}

func (d *Scheme[C, P, F, S]) Open(shares ...*Share[S]) (S, error) {
	var nilS S

	shamirDealer, err := shamir.NewScheme(d.Threshold, d.Total, d.Curve.ScalarField())
	if err != nil {
		return nilS, errs.WrapFailed(err, "could not combine shares")
	}

	result, err := shamirDealer.Open(shares...)
	if err != nil {
		return nilS, errs.WrapFailed(err, "could not combine shares")
	}
	return result, nil
}

func (d *Scheme[C, P, F, S]) VerifyShare(share *Share[S], verificationVector []P) (err error) {
	if len(verificationVector) != int(d.Threshold) {
		return errs.NewFailed("invalid commitment vector")
	}
	if share.SharingId() < 1 || uint(share.SharingId()) > d.Total {
		return errs.NewFailed("invalid sharing id")
	}

	x := types.SharingIDToScalar(share.Id, d.Curve.ScalarField())
	y := polynomials.EvalInExponent(verificationVector, x)
	if !y.Equal(d.Curve.Generator().ScalarMul(share.Value)) {
		return errs.NewFailed("invalid share")
	}

	return nil
}

func (*Scheme[C, P, F, S]) ShareAdd(lhs, rhs *Share[S]) *Share[S] {
	return lhs.Add(rhs)
}

func (*Scheme[C, P, F, S]) ShareAddValue(lhs *Share[S], rhs S) *Share[S] {
	return lhs.AddValue(rhs)
}

func (*Scheme[C, P, F, S]) ShareSub(lhs, rhs *Share[S]) *Share[S] {
	return lhs.Sub(rhs)
}

func (*Scheme[C, P, F, S]) ShareSubValue(lhs *Share[S], rhs S) *Share[S] {
	return lhs.SubValue(rhs)
}

func (*Scheme[C, P, F, S]) ShareNeg(lhs *Share[S]) *Share[S] {
	return lhs.Neg()
}

func (*Scheme[C, P, F, S]) ShareMul(lhs *Share[S], rhs S) *Share[S] {
	return lhs.ScalarMul(rhs)
}

func (*Scheme[C, P, F, S]) VerificationAdd(lhs, rhs []P) []P {
	out := make([]P, len(lhs))
	for i, l := range lhs {
		r := rhs[i]
		out[i] = l.Op(r)
	}
	return out
}

func (d *Scheme[C, P, F, S]) VerificationAddValue(lhs []P, rhs S) []P {
	r := d.Curve.Generator().ScalarMul(rhs)
	out := make([]P, len(lhs))
	for i, l := range lhs {
		if i == 0 {
			out[i] = l.Op(r)
		} else {
			out[i] = l
		}
	}
	return out
}

func (*Scheme[C, P, F, S]) VerificationSub(lhs, rhs []P) []P {
	out := make([]P, len(lhs))
	for i, l := range lhs {
		r := rhs[i]
		out[i] = l.Op(r)
	}
	return out
}

func (d *Scheme[C, P, F, S]) VerificationSubValue(lhs []P, rhs S) []P {
	// TODO(aalireza): add sub to point
	r := d.Curve.Generator().ScalarMul(rhs)
	out := make([]P, len(lhs))
	for i, l := range lhs {
		if i == 0 {
			out[i] = l.Op(r.OpInv())
		} else {
			out[i] = l
		}
	}
	return out
}

func (*Scheme[C, P, F, S]) VerificationNeg(lhs []P) []P {
	//TODO(aalireza): add neg to point
	out := make([]P, len(lhs))
	for i, l := range lhs {
		out[i] = l.OpInv()
	}
	return out
}

func (*Scheme[C, P, F, S]) VerificationMul(lhs []P, rhs S) []P {
	out := make([]P, len(lhs))
	for i, l := range lhs {
		out[i] = l.ScalarMul(rhs)
	}
	return out
}

func (d *Scheme[C, P, F, S]) Validate() error {
	if d == nil {
		return errs.NewIsNil("receiver")
	}
	if d.Total < d.Threshold {
		return errs.NewArgument("total cannot be less than threshold")
	}
	if d.Threshold < 2 {
		return errs.NewArgument("threshold cannot be less than 2")
	}

	// TODO: how?
	//if d.Curve == nil {
	//	return errs.NewIsNil("curve is nil")
	//}
	return nil
}
