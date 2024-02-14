package feldman

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/batch_schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

type Share = shamir.Share

func Verify(share *Share, commitments []curves.Point, verifier compiler.NIVerifier[batch_schnorr.Statement], proof compiler.NIZKPoKProof) (err error) {
	curve := share.Value.ScalarField().Curve()
	if err := share.Validate(curve); err != nil {
		return errs.WrapValidation(err, "share validation failed")
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
	if !lhs.Equal(rhs) {
		return errs.NewVerification("not equal")
	}

	if err := verifier.Verify(commitments, proof); err != nil {
		return errs.NewVerification("invalid proof")
	}

	return nil
}

type Dealer struct {
	Threshold, Total uint
	Curve            curves.Curve

	_ ds.Incomparable
}

func NewDealer(threshold, total uint, curve curves.Curve) (*Dealer, error) {
	dealer := &Dealer{Threshold: threshold, Total: total, Curve: curve}
	if err := dealer.Validate(); err != nil {
		return nil, errs.WrapFailed(err, "invalid dealer")
	}
	return dealer, nil
}

func (f *Dealer) Split(secret curves.Scalar, prover compiler.NIProver[batch_schnorr.Statement, batch_schnorr.Witness], prng io.Reader) (commitments []curves.Point, shares []*Share, proof compiler.NIZKPoKProof, err error) {
	shamirDealer := &shamir.Dealer{
		Threshold: f.Threshold,
		Total:     f.Total,
		Curve:     f.Curve,
	}
	shares, poly, err := shamirDealer.GeneratePolynomialAndShares(secret, prng)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not generate polynomial and shares")
	}
	commitments = make([]curves.Point, f.Threshold)
	for i := range commitments {
		commitments[i] = f.Curve.ScalarBaseMult(poly.Coefficients[i])
	}
	proof, err = prover.Prove(commitments, poly.Coefficients)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "cannot create a proof")
	}
	return commitments, shares, proof, nil
}

func (f *Dealer) LagrangeCoeffs(shares map[uint]*Share) (map[uint]curves.Scalar, error) {
	shamirDealer := &shamir.Dealer{
		Threshold: f.Threshold,
		Total:     f.Total,
		Curve:     f.Curve,
	}
	identities := make([]uint, len(shares))
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
		return errs.NewArgument("total cannot be less than threshold")
	}
	if f.Threshold < 2 {
		return errs.NewArgument("threshold cannot be less than 2")
	}
	if f.Curve == nil {
		return errs.NewIsNil("curve is nil")
	}
	return nil
}
