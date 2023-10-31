package pedersen

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

type Share = shamir.Share

// Dealer Verifiable Secret Sharing Scheme.
type Dealer struct {
	Threshold, Total int
	Curve            curves.Curve
	Generator        curves.Point

	_ types.Incomparable
}

// Verify checks that the share is a valid pedersen VSS share.
func Verify(share, blindShare *Share, blindedCommitments []curves.Point, secondGenerator curves.Point) (err error) {
	curve := secondGenerator.Curve()
	if err := share.Validate(curve); err != nil {
		return errs.WrapVerificationFailed(err, "invalid share")
	}
	if err := blindShare.Validate(curve); err != nil {
		return errs.WrapVerificationFailed(err, "invalid blind share")
	}
	if err := Validate(secondGenerator); err != nil {
		return errs.WrapVerificationFailed(err, "invalid second generator")
	}
	// 1. Compute R = D_0 +  Σ_j=1^t ((j*i) * D_j) as the expected blinded commitment
	i := curve.Scalar().New(uint64(share.Id))
	accumulator := curve.Scalar().One()
	js := make([]curves.Scalar, len(blindedCommitments))
	for j := 1; j < len(blindedCommitments); j++ {
		accumulator = accumulator.Mul(i)
		js[j] = accumulator
	}
	rhs, err := curve.MultiScalarMult(js[1:], blindedCommitments[1:])
	if err != nil {
		return errs.WrapFailed(err, "multiscalarmult failed")
	}
	rhs = rhs.Add(blindedCommitments[0])

	// 2. Compute L = (s * G) + (h * H) as the actual blinded commitment
	g := blindedCommitments[0].Generator().Mul(share.Value)
	h := secondGenerator.Mul(blindShare.Value)
	lhs := g.Add(h)

	// 3. Check that L = R, abort otherwise
	if lhs.Equal(rhs) {
		return nil
	} else {
		return errs.NewVerificationFailed("not equal")
	}
}

// Output contains all the data from calling Split.
type Output struct {
	Blinding                        curves.Scalar
	BlindingShares, SecretShares    []*Share
	Commitments, BlindedCommitments []curves.Point
	Generator                       curves.Point

	_ types.Incomparable
}

// NewDealer creates a new pedersen VSS.
func NewDealer(threshold, total int, generator curves.Point) (*Dealer, error) {
	err := validateInputs(threshold, total, generator)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid inputs to pedersen VSS")
	}

	return &Dealer{Threshold: threshold, Total: total, Curve: generator.Curve(), Generator: generator}, nil
}

func validateInputs(threshold, total int, generator curves.Point) error {
	if total < threshold {
		return errs.NewInvalidArgument("total cannot be less than threshold")
	}
	if threshold < 2 {
		return errs.NewInvalidArgument("threshold cannot be less than 2")
	}
	if generator == nil {
		return errs.NewIsNil("generator is nil")
	}
	if !generator.IsOnCurve() {
		return errs.NewMembershipError("invalid generator")
	}
	if generator.IsIdentity() {
		return errs.NewIsIdentity("invalid generator")
	}
	return nil
}

// Split creates the verifiers, blinding and shares.
func (pd Dealer) Split(secret curves.Scalar, prng io.Reader) (*Output, error) {
	// generate a random blinding factor
	blinding := pd.Curve.Scalar().Random(prng)

	shamirDealer := shamir.Dealer{
		Threshold: pd.Threshold,
		Total:     pd.Total,
		Curve:     pd.Curve,
	}
	// split the secret into shares
	shares, poly, err := shamirDealer.GeneratePolynomialAndShares(secret, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate polynomial and shares")
	}

	// split the blinding into shares
	blindingShares, polyBlinding, err := shamirDealer.GeneratePolynomialAndShares(blinding, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not generate polynomial and shares")
	}

	// Generate the verifiable commitments to the polynomial for the shares
	blindedCommitments := make([]curves.Point, pd.Threshold)
	commitments := make([]curves.Point, pd.Threshold)

	// ({p0 * G + b0 * H}, ...,{pt * G + bt * H})
	for i, c := range poly.Coefficients {
		s := pd.Curve.ScalarBaseMult(c)
		b := pd.Generator.Mul(polyBlinding.Coefficients[i])
		bv := s.Add(b)
		blindedCommitments[i] = bv
		commitments[i] = s
	}

	return &Output{
		Blinding: blinding, BlindingShares: blindingShares, SecretShares: shares, Commitments: commitments, BlindedCommitments: blindedCommitments, Generator: pd.Generator,
	}, nil
}

func (pd Dealer) LagrangeCoefficients(shares map[int]*Share) (map[int]curves.Scalar, error) {
	shamirDealer := &shamir.Dealer{
		Threshold: pd.Threshold,
		Total:     pd.Total,
		Curve:     pd.Curve,
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

func (pd Dealer) Combine(shares ...*Share) (curves.Scalar, error) {
	shamirDealer := &shamir.Dealer{
		Threshold: pd.Threshold,
		Total:     pd.Total,
		Curve:     pd.Curve,
	}
	result, err := shamirDealer.Combine(shares...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not combine shares")
	}
	return result, nil
}

func (pd Dealer) CombinePoints(shares ...*Share) (curves.Point, error) {
	shamirDealer := &shamir.Dealer{
		Threshold: pd.Threshold,
		Total:     pd.Total,
		Curve:     pd.Curve,
	}
	result, err := shamirDealer.CombinePoints(shares...)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not combine points")
	}
	return result, nil
}

func Validate(secondGenerator curves.Point) error {
	if secondGenerator == nil {
		return errs.NewIsNil("second generator is nil")
	}
	if !secondGenerator.IsOnCurve() {
		return errs.NewMembershipError("invalid second generator")
	}
	if secondGenerator.IsIdentity() {
		return errs.NewIsIdentity("invalid second generator")
	}
	if secondGenerator.Equal(secondGenerator.Curve().Generator()) {
		return errs.NewInvalidArgument("second generator is equal to curve generator")
	}
	return nil
}
