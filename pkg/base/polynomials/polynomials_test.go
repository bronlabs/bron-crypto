package polynomials_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/k256"
	p "github.com/copperexchange/knox-primitives/pkg/base/polynomials"
)

func TestNewPoly(t *testing.T) {
	t.Parallel()
	curve := bls12381.NewG1()
	secret := curve.Scalar().Hash([]byte("test"))

	poly, err := p.NewRandomPolynomial(secret, 4, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, poly)

	require.Equal(t, poly.Coefficients[0], secret)
}

func TestLi(t *testing.T) {
	t.Parallel()
	curve := k256.New()
	for _, test := range []struct {
		i        int
		xs       []int
		x        int
		expected int
		name     string
	}{
		{
			i:        1,
			xs:       []int{0, 1, 2},
			x:        1,
			expected: 1,
			name:     "basic case",
		},
		{
			i:        1,
			xs:       []int{0, 1, 2},
			x:        0,
			expected: 0,
			name:     "another base case",
		},
		{
			i:        2,
			xs:       []int{-2, 0, 2},
			x:        2,
			expected: 1,
			name:     "larger interval",
		},
		{
			i:        0,
			xs:       []int{1},
			x:        1,
			expected: 1,
			name:     "signle data point",
		},
		{
			i:        1,
			xs:       []int{-3, -2, -1},
			x:        -2,
			expected: 1,
			name:     "all negative xs",
		},
		{
			i:        1,
			xs:       []int{-3, 0, 3},
			x:        0,
			expected: 1,
			name:     "mixed x values",
		},
		{
			i:        1,
			xs:       []int{0, 1, 2},
			x:        3,
			expected: -3,
			name:     "behaviour outside the given points",
		},
	} {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sign := 1
			if tt.x < 0 {
				sign = -1
			}
			xScalar := curve.Scalar().New(uint64(sign * tt.x))
			if sign == -1 {
				xScalar = xScalar.Neg()
			}
			xsScalar := make([]curves.Scalar, len(tt.xs))
			for i := 0; i < len(tt.xs); i++ {
				sign := 1
				if tt.xs[i] < 0 {
					sign = -1
				}
				xsScalar[i] = curve.Scalar().New(uint64(sign * tt.xs[i]))
				if sign == -1 {
					xsScalar[i] = xsScalar[i].Neg()
				}
			}
			sign2 := 1
			if tt.expected < 0 {
				sign2 = -1
			}
			expectedScalar := curve.Scalar().New(uint64(sign2 * tt.expected))
			if sign2 == -1 {
				expectedScalar = expectedScalar.Neg()
			}
			actual, err := p.L_i(curve, tt.i, xsScalar, xScalar)
			require.NoError(t, err)
			require.Exactly(t, expectedScalar, actual)
		})
	}
}

func TestAllBasisPolynomials(t *testing.T) {
	t.Parallel()
	curve := k256.New()
	for _, test := range []struct {
		xs       []int
		x        int
		expected map[int]int
		name     string
	}{
		{
			xs: []int{0, 1, 2},
			x:  1,
			expected: map[int]int{
				0: 0,
				1: 1,
				2: 0,
			},
			name: "basic case",
		},
		{
			xs: []int{0, 1, 2},
			x:  0,
			expected: map[int]int{
				0: 1,
				1: 0,
				2: 0,
			},
			name: "another basic case",
		},
		{
			xs: []int{-2, 0, 2},
			x:  2,
			expected: map[int]int{
				0: 0,
				1: 0,
				2: 1,
			},
			name: "larger intervals",
		},
		{
			xs: []int{0, 1, 2, 3},
			x:  2,
			expected: map[int]int{
				0: 0,
				1: 0,
				2: 1,
				3: 0,
			},
			name: "more data points",
		},
		{
			xs: []int{1},
			x:  1,
			expected: map[int]int{
				0: 1,
			},
			name: "single data point",
		},
		{
			xs: []int{-3, -2, -1},
			x:  -2,
			expected: map[int]int{
				0: 0,
				1: 1,
				2: 0,
			},
			name: "all negative x values",
		},
		{
			xs: []int{-3, -2, -1},
			x:  2,
			expected: map[int]int{
				0: 6,
				1: -15,
				2: 10,
			},
			name: "all negative x values",
		},
		{
			xs: []int{-3, 0, 3},
			x:  0,
			expected: map[int]int{
				0: 0,
				1: 1,
				2: 0,
			},
			name: "mixed x values",
		},
		{
			xs: []int{0, 1, 2},
			x:  3,
			expected: map[int]int{
				0: 1,
				1: -3,
				2: 3,
			},
			name: "outside range",
		},
	} {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			signX := 1
			if tt.x < 0 {
				signX = -1
			}
			xScalar := curve.Scalar().New(uint64(signX * tt.x))
			if signX == -1 {
				xScalar = xScalar.Neg()
			}
			xsScalar := make([]curves.Scalar, len(tt.xs))
			for i := 0; i < len(tt.xs); i++ {
				signXs := 1
				if tt.xs[i] < 0 {
					signXs = -1
				}
				xsScalar[i] = curve.Scalar().New(uint64(signXs * tt.xs[i]))
				if signXs == -1 {
					xsScalar[i] = xsScalar[i].Neg()
				}
			}
			expectedScalar := make(map[int]curves.Scalar, len(tt.expected))
			for k, v := range tt.expected {
				signV := 1
				if v < 0 {
					signV = -1
				}
				expectedScalar[k] = curve.Scalar().New(uint64(signV * v))
				if signV == -1 {
					expectedScalar[k] = expectedScalar[k].Neg()
				}
			}
			actual, err := p.LagrangeBasis(curve, xsScalar, xScalar)
			require.NoError(t, err)
			require.Exactly(t, expectedScalar, actual)
		})
	}
}
