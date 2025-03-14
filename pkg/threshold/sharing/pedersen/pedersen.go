package pedersen

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

type Share = shamir.Share

// Dealer Verifiable Secret Sharing Scheme.
type Dealer struct {
	Threshold, Total uint
	Curve            curves.Curve
	Generator        curves.Point

	_ ds.Incomparable
}

func Verify(share, blindShare *Share, commitments []curves.Point, generator curves.Point) (err error) {
	curve := generator.Curve()
	if err := share.Validate(curve); err != nil {
		return errs.WrapValidation(err, "invalid share")
	}
	if err := blindShare.Validate(curve); err != nil {
		return errs.WrapValidation(err, "invalid blind share")
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

	g := commitments[0].Curve().Generator().ScalarMul(share.Value)
	h := generator.ScalarMul(blindShare.Value)
	lhs := g.Add(h)

	if lhs.Equal(rhs) {
		return nil
	} else {
		return errs.NewVerification("not equal")
	}
}

// Output contains all the data from calling Split.
type Output struct {
	Blinding                        curves.Scalar
	BlindingShares, SecretShares    []*Share
	Commitments, BlindedCommitments []curves.Point
	PolynomialCoefficients          []curves.Scalar
	Generator                       curves.Point

	_ ds.Incomparable
}

// NewDealer creates a new pedersen VSS.
func NewDealer(threshold, total uint, generator curves.Point) (*Dealer, error) {
	err := validateInputs(threshold, total, generator)
	if err != nil {
		return nil, errs.WrapArgument(err, "invalid inputs to pedersen VSS")
	}

	return &Dealer{Threshold: threshold, Total: total, Curve: generator.Curve(), Generator: generator}, nil
}

func validateInputs(threshold, total uint, generator curves.Point) error {
	if total < threshold {
		return errs.NewArgument("total cannot be less than threshold")
	}
	if threshold < 2 {
		return errs.NewArgument("threshold cannot be less than 2")
	}
	if generator == nil {
		return errs.NewIsNil("generator is nil")
	}
	if generator.IsAdditiveIdentity() {
		return errs.NewIsIdentity("invalid generator")
	}
	return nil
}

// Split creates the verifiers, blinding and shares.
func (pd Dealer) Split(secret curves.Scalar, prng io.Reader) (*Output, error) {
	// generate a random blinding factor
	blinding, err := pd.Curve.ScalarField().Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "could not generate random scalar")
	}

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
		b := pd.Generator.ScalarMul(polyBlinding.Coefficients[i])
		bv := s.Add(b)
		blindedCommitments[i] = bv
		commitments[i] = s
	}

	return &Output{
		Blinding:               blinding,
		BlindingShares:         blindingShares,
		SecretShares:           shares,
		Commitments:            commitments,
		BlindedCommitments:     blindedCommitments,
		PolynomialCoefficients: poly.Coefficients,
		Generator:              pd.Generator,
	}, nil
}

func (pd Dealer) LagrangeCoefficients(shares map[uint]*Share) (map[uint]curves.Scalar, error) {
	shamirDealer := &shamir.Dealer{
		Threshold: pd.Threshold,
		Total:     pd.Total,
		Curve:     pd.Curve,
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
