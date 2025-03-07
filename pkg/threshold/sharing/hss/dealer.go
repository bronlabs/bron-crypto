package hss

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"io"
	"slices"
)

func Share(secret curves.Scalar, thresholds []uint, totals []uint, prng io.Reader) ([]*HierarchicalShare, error) {
	coefficients := make([]curves.Scalar, thresholds[len(thresholds)-1])
	coefficients[0] = secret
	for i := 1; i < len(coefficients); i++ {
		var err error
		coefficients[i], err = secret.ScalarField().Random(prng)
		if err != nil {
			return nil, err
		}
	}
	polynomial := NewPolynomial(coefficients)

	var shares []*HierarchicalShare
	for level := range thresholds {
		levelDerivativeDegree := uint(0)
		if level > 0 {
			levelDerivativeDegree = thresholds[level-1]
		}
		levelPolynomial := polynomial.Derivative(levelDerivativeDegree)
		for id := uint(1); id <= totals[level]; id++ {
			shares = append(shares, &HierarchicalShare{
				I:     id,
				J:     levelDerivativeDegree,
				Value: levelPolynomial.EvalAt(secret.ScalarField().New(uint64(id))),
			})
		}
	}

	return shares, nil
}

func Reconstruct(shares ...*HierarchicalShare) (curves.Scalar, error) {
	sortedShares := slices.SortedFunc(slices.Values(shares), func(l, r *HierarchicalShare) int {
		if l.I < r.I {
			return -1
		}
		if l.I > r.I {
			return 1
		}
		if l.J < r.J {
			return -1
		}
		if l.J > r.J {
			return 1
		}
		return 0
	})

	m := NewEmptyMatrix(uint(len(shares)), uint(len(shares)))
	for r := range shares {
		for c := range shares {
			i := sortedShares[r].I
			j := sortedShares[r].J
			vc := make([]curves.Scalar, c+1)
			for i := range vc {
				if i == len(vc)-1 {
					vc[i] = shares[0].Value.ScalarField().MultiplicativeIdentity()
				} else {
					vc[i] = shares[0].Value.ScalarField().AdditiveIdentity()
				}
			}
			monomial := NewPolynomial(vc)
			v := monomial.Derivative(j).EvalAt(shares[0].Value.ScalarField().New(uint64(i)))
			m.Set(r, int(c), v)
		}
	}
	m0 := m.Clone()
	for i := range shares {
		m0.Set(i, 0, sortedShares[i].Value)
	}

	nom := m0.Determinant()
	den := m.Determinant()
	if den.IsAdditiveIdentity() {
		return nil, errs.NewFailed("cannot reconstruct secret")
	}
	secret, _ := nom.Div(den)
	return secret, nil
}
