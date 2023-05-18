//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package sharing

import (
	"fmt"
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/pkg/errors"
)

// Pedersen Verifiable Secret Sharing Scheme
type Pedersen struct {
	threshold, limit int
	curve            *curves.Curve
	generator        curves.Point
}

func PedersenVerify(share, blindShare *ShamirShare, commitments []curves.Point, generator curves.Point) (err error) {
	curve, err := curves.GetCurveByName(generator.CurveName())
	if err != nil {
		return errors.WithStack(err)
	}
	if err := share.Validate(curve); err != nil {
		return err
	}
	if err := blindShare.Validate(curve); err != nil {
		return err
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
		return fmt.Errorf("not equal")
	}
}

// PedersenResult contains all the data from calling Split
type PedersenResult struct {
	Blinding                         curves.Scalar
	BlindingShares, SecretShares     []*ShamirShare
	Commitments, BlindingCommitments []curves.Point
	Generator                        curves.Point
}

// NewPedersen creates a new pedersen VSS
func NewPedersen(threshold, limit int, generator curves.Point) (*Pedersen, error) {
	if limit < threshold {
		return nil, fmt.Errorf("limit cannot be less than threshold")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("threshold cannot be less than 2")
	}
	if generator == nil {
		return nil, fmt.Errorf("invalid generator")
	}
	curve, err := curves.GetCurveByName(generator.CurveName())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if !generator.IsOnCurve() || generator.IsIdentity() {
		return nil, fmt.Errorf("invalid generator")
	}
	return &Pedersen{threshold, limit, curve, generator}, nil
}

// Split creates the verifiers, blinding and shares
func (pd Pedersen) Split(secret curves.Scalar, reader io.Reader) (*PedersenResult, error) {
	// generate a random blinding factor
	blinding := pd.curve.Scalar.Random(reader)

	shamir := Shamir{pd.threshold, pd.limit, pd.curve}
	// split the secret into shares
	shares, poly := shamir.getPolyAndShares(secret, reader)

	// split the blinding into shares
	blindingShares, polyBlinding := shamir.getPolyAndShares(blinding, reader)

	// Generate the verifiable commitments to the polynomial for the shares
	blindedCommitments := make([]curves.Point, pd.threshold)
	commitments := make([]curves.Point, pd.threshold)

	// ({p0 * G + b0 * H}, ...,{pt * G + bt * H})
	for i, c := range poly.Coefficients {
		s := pd.curve.ScalarBaseMult(c)
		b := pd.generator.Mul(polyBlinding.Coefficients[i])
		bv := s.Add(b)
		blindedCommitments[i] = bv
		commitments[i] = s
	}

	return &PedersenResult{
		blinding, blindingShares, shares, commitments, blindedCommitments, pd.generator,
	}, nil
}

func (pd Pedersen) LagrangeCoeffs(shares map[int]*ShamirShare) (map[int]curves.Scalar, error) {
	shamir := &Shamir{
		threshold: pd.threshold,
		limit:     pd.limit,
		curve:     pd.curve,
	}
	identities := make([]int, 0)
	for _, xi := range shares {
		identities = append(identities, xi.Id)
	}
	return shamir.LagrangeCoeffs(identities)
}

func (pd Pedersen) Combine(shares ...*ShamirShare) (curves.Scalar, error) {
	shamir := &Shamir{
		threshold: pd.threshold,
		limit:     pd.limit,
		curve:     pd.curve,
	}
	return shamir.Combine(shares...)
}

func (pd Pedersen) CombinePoints(shares ...*ShamirShare) (curves.Point, error) {
	shamir := &Shamir{
		threshold: pd.threshold,
		limit:     pd.limit,
		curve:     pd.curve,
	}
	return shamir.CombinePoints(shares...)
}
