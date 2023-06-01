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

func FeldmanVerify(share *ShamirShare, commitments []curves.Point) (err error) {
	curve, err := curves.GetCurveByName(commitments[0].CurveName())
	if err != nil {
		return errors.WithStack(err)
	}
	err = share.Validate(curve)
	if err != nil {
		return err
	}
	x := curve.Scalar.New(share.Id)
	i := curve.Scalar.One()
	rhs := commitments[0]

	for j := 1; j < len(commitments); j++ {
		i = i.Mul(x)
		rhs = rhs.Add(commitments[j].Mul(i))
	}

	lhs := commitments[0].Generator().Mul(share.Value)
	if lhs.Equal(rhs) {
		return nil
	} else {
		return fmt.Errorf("not equal")
	}
}

type Feldman struct {
	Threshold, Limit int
	Curve            *curves.Curve
}

func NewFeldman(threshold, limit int, curve *curves.Curve) (*Feldman, error) {
	if limit < threshold {
		return nil, fmt.Errorf("limit cannot be less than threshold")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("threshold cannot be less than 2")
	}
	if curve == nil {
		return nil, fmt.Errorf("invalid curve")
	}

	return &Feldman{threshold, limit, curve}, nil
}

func (f Feldman) Split(secret curves.Scalar, prng io.Reader) (commitments []curves.Point, shares []*ShamirShare, err error) {
	if secret.IsZero() {
		return nil, nil, fmt.Errorf("invalid secret")
	}
	shamir := &Shamir{
		threshold: f.Threshold,
		limit:     f.Limit,
		curve:     f.Curve,
	}
	shares, poly := shamir.getPolyAndShares(secret, prng)
	commitments = make([]curves.Point, f.Threshold)
	for i := range commitments {
		commitments[i] = f.Curve.ScalarBaseMult(poly.Coefficients[i])
	}
	return commitments, shares, nil
}

func (f Feldman) LagrangeCoeffs(shares map[int]*ShamirShare) (map[int]curves.Scalar, error) {
	shamir := &Shamir{
		threshold: f.Threshold,
		limit:     f.Limit,
		curve:     f.Curve,
	}
	identities := make([]int, 0)
	for _, xi := range shares {
		identities = append(identities, xi.Id)
	}
	return shamir.LagrangeCoeffs(identities)
}

func (f Feldman) Combine(shares ...*ShamirShare) (curves.Scalar, error) {
	shamir := &Shamir{
		threshold: f.Threshold,
		limit:     f.Limit,
		curve:     f.Curve,
	}
	return shamir.Combine(shares...)
}

func (f Feldman) CombinePoints(shares ...*ShamirShare) (curves.Point, error) {
	shamir := &Shamir{
		threshold: f.Threshold,
		limit:     f.Limit,
		curve:     f.Curve,
	}
	return shamir.CombinePoints(shares...)
}
