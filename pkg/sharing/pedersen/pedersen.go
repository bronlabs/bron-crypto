package pedersen

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/sharing/shamir"
)

type Share = shamir.Share

// Dealer Verifiable Secret Sharing Scheme.
type Dealer struct {
	Threshold, Total int
	Curve            curves.Curve
	Generator        curves.Point

	_ helper_types.Incomparable
}

func Verify(share, blindShare *Share, commitments []curves.Point, generator curves.Point) (err error) {
	curve, err := generator.Curve()
	if err != nil {
		return errs.WrapInvalidCurve(err, "no such curve: %s", curve.Name())
	}
	if err := share.Validate(curve); err != nil {
		return errs.WrapVerificationFailed(err, "invalid share")
	}
	if err := blindShare.Validate(curve); err != nil {
		return errs.WrapVerificationFailed(err, "invalid blind share")
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

	g := commitments[0].Generator().Mul(share.Value)
	h := generator.Mul(blindShare.Value)
	lhs := g.Add(h)

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

	_ helper_types.Incomparable
}

// NewDealer creates a new pedersen VSS.
func NewDealer(threshold, total int, generator curves.Point) (*Dealer, error) {
	if total < threshold {
		return nil, errs.NewInvalidArgument("total cannot be less than threshold")
	}
	if threshold < 2 {
		return nil, errs.NewInvalidArgument("threshold cannot be less than 2")
	}
	if generator == nil {
		return nil, errs.NewIsNil("generator is nil")
	}
	curve, err := generator.Curve()
	if err != nil {
		return nil, errs.NewInvalidCurve("no such curve: %s", curve.Name())
	}
	if !generator.IsOnCurve() {
		return nil, errs.NewMembershipError("invalid generator")
	}
	if generator.IsIdentity() {
		return nil, errs.NewIsIdentity("invalid generator")
	}

	return &Dealer{Threshold: threshold, Total: total, Curve: curve, Generator: generator}, nil
}

// Split creates the verifiers, blinding and shares.
func (pd Dealer) Split(secret curves.Scalar, prng io.Reader) *Output {
	// generate a random blinding factor
	blinding := pd.Curve.Scalar().Random(prng)

	shamirDealer := shamir.Dealer{
		Threshold: pd.Threshold,
		Total:     pd.Total,
		Curve:     pd.Curve,
	}
	// split the secret into shares
	shares, poly := shamirDealer.GeneratePolynomialAndShares(secret, prng)

	// split the blinding into shares
	blindingShares, polyBlinding := shamirDealer.GeneratePolynomialAndShares(blinding, prng)

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
	}
}

func (pd Dealer) LagrangeCoefficients(shares map[int]*Share) (map[int]curves.Scalar, error) {
	shamirDealer := &shamir.Dealer{
		Threshold: pd.Threshold,
		Total:     pd.Total,
		Curve:     pd.Curve,
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
