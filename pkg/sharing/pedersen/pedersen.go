package pedersen

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/shamir"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
)

type Share = shamir.Share

// Dealer Verifiable Secret Sharing Scheme
type Dealer struct {
	Threshold, Total int
	Curve            *curves.Curve
	Generator        curves.Point
}

func Verify(share, blindShare *Share, commitments []curves.Point, generator curves.Point) (err error) {
	curve, err := curves.GetCurveByName(generator.CurveName())
	if err != nil {
		return errs.WrapInvalidCurve(err, "no such curve: %s", generator.CurveName())
	}
	if err := share.Validate(curve); err != nil {
		return errs.WrapVerificationFailed(err, "invalid share")
	}
	if err := blindShare.Validate(curve); err != nil {
		return errs.WrapVerificationFailed(err, "invalid blind share")
	}

	x := curve.Scalar.New(share.Id)
	i := curve.Scalar.One()
	rhs := commitments[0]

	for j := 1; j < len(commitments); j++ {
		i = i.Mul(x)
		rhs = rhs.Add(commitments[j].Mul(i))
	}

	g := commitments[0].Generator().Mul(share.Value)
	h := generator.Mul(blindShare.Value)
	lhs := g.Add(h)

	if lhs.Equal(rhs) {
		return nil
	} else {
		return errs.NewVerificationFailed("not equal")
	}
}

// Output contains all the data from calling Split
type Output struct {
	Blinding                        curves.Scalar
	BlindingShares, SecretShares    []*Share
	Commitments, BlindedCommitments []curves.Point
	Generator                       curves.Point
}

// NewDealer creates a new pedersen VSS
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
	curve, err := curves.GetCurveByName(generator.CurveName())
	if err != nil {
		return nil, errs.NewInvalidCurve("no such curve: %s", generator.CurveName())
	}
	if !generator.IsOnCurve() {
		return nil, errs.NewNotOnCurve("invalid generator")
	}
	if generator.IsIdentity() {
		return nil, errs.NewIsIdentity("invalid generator")
	}

	return &Dealer{threshold, total, curve, generator}, nil
}

// Split creates the verifiers, blinding and shares
func (pd Dealer) Split(secret curves.Scalar, prng io.Reader) *Output {
	// generate a random blinding factor
	blinding := pd.Curve.Scalar.Random(prng)

	shamir := shamir.Dealer{
		Threshold: pd.Threshold,
		Total:     pd.Total,
		Curve:     pd.Curve,
	}
	// split the secret into shares
	shares, poly := shamir.GeneratePolynomialAndShares(secret, prng)

	// split the blinding into shares
	blindingShares, polyBlinding := shamir.GeneratePolynomialAndShares(blinding, prng)

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
		blinding, blindingShares, shares, commitments, blindedCommitments, pd.Generator,
	}
}

func (pd Dealer) LagrangeCoefficients(shares map[int]*Share) (map[int]curves.Scalar, error) {
	shamir := &shamir.Dealer{
		Threshold: pd.Threshold,
		Total:     pd.Total,
		Curve:     pd.Curve,
	}
	identities := make([]int, 0)
	for _, xi := range shares {
		identities = append(identities, xi.Id)
	}
	return shamir.LagrangeCoefficients(identities)
}

func (pd Dealer) Combine(shares ...*Share) (curves.Scalar, error) {
	shamir := &shamir.Dealer{
		Threshold: pd.Threshold,
		Total:     pd.Total,
		Curve:     pd.Curve,
	}
	return shamir.Combine(shares...)
}

func (pd Dealer) CombinePoints(shares ...*Share) (curves.Point, error) {
	shamir := &shamir.Dealer{
		Threshold: pd.Threshold,
		Total:     pd.Total,
		Curve:     pd.Curve,
	}
	return shamir.CombinePoints(shares...)
}
