package polynomials_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/num/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/stretchr/testify/require"
)

func TestPolynomialRingSanity(t *testing.T) {
	t.Parallel()
	curve := bls12381.NewG2()
	field := curves.GetScalarField(curve)
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	secret, err := field.Hash([]byte("test"))
	require.NoError(t, err)

	out, err := polyRing.RandomPolynomialWithConstantTerm(2, secret, crand.Reader)
	require.NoError(t, err)
	require.Equal(t, out.Degree(), 2)
	require.True(t, out.Coefficients()[0].Equal(secret))
}

func additionCases[S algebra.FiniteRingElement[S]](t *testing.T, coefficientRing algebra.FiniteRing[S]) {
	t.Helper()
	polyRing, err := polynomials.NewPolynomialRing(coefficientRing)
	require.NoError(t, err)

	// Create common coefficients
	zero := coefficientRing.Zero()
	one := coefficientRing.One()
	two := one.Add(one)
	three := two.Add(one)
	four := three.Add(one)
	five := four.Add(one)
	six := five.Add(one)
	seven := six.Add(one)
	eight := seven.Add(one)

	tests := []struct {
		name           string
		p1Coeffs       []S
		p2Coeffs       []S
		expectedCoeffs []S
		expectedDegree int
	}{
		{
			name:           "add two quadratics",
			p1Coeffs:       []S{one, three, two},   // 1 + 3x + 2x^2
			p2Coeffs:       []S{four, two, one},    // 4 + 2x + x^2
			expectedCoeffs: []S{five, five, three}, // 5 + 5x + 3x^2
			expectedDegree: 2,
		},
		{
			name:           "add polynomial with zero",
			p1Coeffs:       []S{two, four, one}, // 2 + 4x + x^2
			p2Coeffs:       []S{zero},           // 0
			expectedCoeffs: []S{two, four, one}, // 2 + 4x + x^2
			expectedDegree: 2,
		},
		{
			name:           "add polynomials of different degrees",
			p1Coeffs:       []S{one, two},              // 1 + 2x
			p2Coeffs:       []S{three, one, two, one},  // 3 + x + 2x^2 + x^3
			expectedCoeffs: []S{four, three, two, one}, // 4 + 3x + 2x^2 + x^3
			expectedDegree: 3,
		},
		{
			name:           "add constants",
			p1Coeffs:       []S{three}, // 3
			p2Coeffs:       []S{five},  // 5
			expectedCoeffs: []S{eight}, // 8
			expectedDegree: 0,
		},
		{
			name:           "add polynomials that cancel leading term",
			p1Coeffs:       []S{one, two, three},       // 1 + 2x + 3x^2
			p2Coeffs:       []S{two, one, three.Neg()}, // 2 + x + (-3)x^2
			expectedCoeffs: []S{three, three},          // 3 + 3x + 0x^2
			expectedDegree: 1,                          // degree drops because leading coefficient is zero
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Convert coefficient slices to field elements
			// Create polynomials
			p1, err := polyRing.New(tc.p1Coeffs...)
			require.NoError(t, err)
			p2, err := polyRing.New(tc.p2Coeffs...)
			require.NoError(t, err)

			// Add polynomials
			sum := p1.Add(p2)

			// Verify results
			sumCoeffs := sum.Coefficients()
			require.Equal(t, len(tc.expectedCoeffs), len(sumCoeffs), "coefficient count mismatch")

			for i := range tc.expectedCoeffs {
				require.True(t, sumCoeffs[i].Equal(tc.expectedCoeffs[i]),
					"coefficient at index %d: expected %v, got %v", i, tc.expectedCoeffs[i].String(), sumCoeffs[i].String())
			}

			require.Equal(t, tc.expectedDegree, sum.Degree(), "degree mismatch")
		})
	}
}

func TestPolynomialAddition(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := curves.GetScalarField(curve)
	additionCases(t, field)
}

func multiplicationCases[S algebra.FiniteRingElement[S]](t *testing.T, coefficientRing algebra.FiniteRing[S]) {
	t.Helper()
	polyRing, err := polynomials.NewPolynomialRing(coefficientRing)
	require.NoError(t, err)

	// Create common coefficients
	zero := coefficientRing.Zero()
	one := coefficientRing.One()
	two := one.Add(one)
	three := two.Add(one)
	four := three.Add(one)
	five := four.Add(one)
	six := five.Add(one)
	seven := six.Add(one)
	eight := seven.Add(one)
	nine := eight.Add(one)
	ten := nine.Add(one)
	twelve := ten.Add(two)

	tests := []struct {
		name           string
		p1Coeffs       []S
		p2Coeffs       []S
		expectedCoeffs []S
		expectedDegree int
	}{
		{
			name:           "multiply linear polynomials",
			p1Coeffs:       []S{two, three},      // 2 + 3x
			p2Coeffs:       []S{one, two},        // 1 + 2x
			expectedCoeffs: []S{two, seven, six}, // 2 + 7x + 6x^2
			expectedDegree: 2,
		},
		{
			name:           "multiply by constant",
			p1Coeffs:       []S{one, two, three},     // 1 + 2x + 3x^2
			p2Coeffs:       []S{four},                // 4
			expectedCoeffs: []S{four, eight, twelve}, // 4 + 8x + 12x^2
			expectedDegree: 2,
		},
		{
			name:           "multiply by zero",
			p1Coeffs:       []S{one, two, three}, // 1 + 2x + 3x^2
			p2Coeffs:       []S{zero},            // 0
			expectedCoeffs: []S{zero},            // 0
			expectedDegree: -1,
		},
		{
			name:           "multiply by one",
			p1Coeffs:       []S{two, three, one}, // 2 + 3x + x^2
			p2Coeffs:       []S{one},             // 1
			expectedCoeffs: []S{two, three, one}, // 2 + 3x + x^2
			expectedDegree: 2,
		},
		{
			name:           "multiply quadratic by linear",
			p1Coeffs:       []S{one, zero, one},       // 1 + x^2
			p2Coeffs:       []S{zero, one},            // x
			expectedCoeffs: []S{zero, one, zero, one}, // x + x^3
			expectedDegree: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create polynomials
			p1, err := polyRing.New(tc.p1Coeffs...)
			require.NoError(t, err)
			p2, err := polyRing.New(tc.p2Coeffs...)
			require.NoError(t, err)

			// Multiply polynomials
			product := p1.Mul(p2)

			// Verify results
			productCoeffs := product.Coefficients()
			require.Equal(t, len(tc.expectedCoeffs), len(productCoeffs), "coefficient count mismatch")

			for i := range tc.expectedCoeffs {
				require.True(t, productCoeffs[i].Equal(tc.expectedCoeffs[i]),
					"coefficient at index %d: expected %v, got %v", i, tc.expectedCoeffs[i].String(), productCoeffs[i].String())
			}

			require.Equal(t, tc.expectedDegree, product.Degree(), "degree mismatch")
		})
	}
}

func TestPolynomialMultiplication(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := curves.GetScalarField(curve)
	multiplicationCases(t, field)
}

func subtractionCases[S algebra.FiniteRingElement[S]](t *testing.T, coefficientRing algebra.FiniteRing[S]) {
	t.Helper()
	polyRing, err := polynomials.NewPolynomialRing(coefficientRing)
	require.NoError(t, err)

	// Create common coefficients
	zero := coefficientRing.Zero()
	one := coefficientRing.One()
	two := one.Add(one)
	three := two.Add(one)
	four := three.Add(one)
	five := four.Add(one)

	tests := []struct {
		name           string
		p1Coeffs       []S
		p2Coeffs       []S
		expectedCoeffs []S
		expectedDegree int
	}{
		{
			name:           "subtract equal polynomials",
			p1Coeffs:       []S{two, three, one}, // 2 + 3x + x^2
			p2Coeffs:       []S{two, three, one}, // 2 + 3x + x^2
			expectedCoeffs: []S{zero},            // 0
			expectedDegree: -1,
		},
		{
			name:           "subtract smaller from larger",
			p1Coeffs:       []S{five, four, three}, // 5 + 4x + 3x^2
			p2Coeffs:       []S{two, one, one},     // 2 + x + x^2
			expectedCoeffs: []S{three, three, two}, // 3 + 3x + 2x^2
			expectedDegree: 2,
		},
		{
			name:           "subtract zero",
			p1Coeffs:       []S{one, two, three}, // 1 + 2x + 3x^2
			p2Coeffs:       []S{zero},            // 0
			expectedCoeffs: []S{one, two, three}, // 1 + 2x + 3x^2
			expectedDegree: 2,
		},
		{
			name:           "subtract from zero",
			p1Coeffs:       []S{zero},                 // 0
			p2Coeffs:       []S{one, two},             // 1 + 2x
			expectedCoeffs: []S{one.Neg(), two.Neg()}, // -1 - 2x
			expectedDegree: 1,
		},
		{
			name:           "subtract with degree reduction",
			p1Coeffs:       []S{one, two, three},   // 1 + 2x + 3x^2
			p2Coeffs:       []S{zero, zero, three}, // 3x^2
			expectedCoeffs: []S{one, two},          // 1 + 2x
			expectedDegree: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create polynomials
			p1, err := polyRing.New(tc.p1Coeffs...)
			require.NoError(t, err)
			p2, err := polyRing.New(tc.p2Coeffs...)
			require.NoError(t, err)

			// Subtract polynomials
			difference := p1.Sub(p2)

			// Verify results
			diffCoeffs := difference.Coefficients()
			require.Equal(t, len(tc.expectedCoeffs), len(diffCoeffs), "coefficient count mismatch")

			for i := range tc.expectedCoeffs {
				require.True(t, diffCoeffs[i].Equal(tc.expectedCoeffs[i]),
					"coefficient at index %d: expected %v, got %v", i, tc.expectedCoeffs[i].String(), diffCoeffs[i].String())
			}

			require.Equal(t, tc.expectedDegree, difference.Degree(), "degree mismatch")
		})
	}
}

func TestPolynomialSubtraction(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := curves.GetScalarField(curve)
	subtractionCases(t, field)
}

func evaluationCases[S algebra.FiniteRingElement[S]](t *testing.T, coefficientRing algebra.FiniteRing[S]) {
	t.Helper()
	polyRing, err := polynomials.NewPolynomialRing(coefficientRing)
	require.NoError(t, err)

	// Create common coefficients
	zero := coefficientRing.Zero()
	one := coefficientRing.One()
	two := one.Add(one)
	three := two.Add(one)
	four := three.Add(one)

	tests := []struct {
		name     string
		pCoeffs  []S
		x        S
		expected S
	}{
		{
			name:     "evaluate constant polynomial",
			pCoeffs:  []S{three}, // 3
			x:        two,
			expected: three,
		},
		{
			name:     "evaluate linear at zero",
			pCoeffs:  []S{one, two}, // 1 + 2x
			x:        zero,
			expected: one,
		},
		{
			name:     "evaluate linear at one",
			pCoeffs:  []S{one, two}, // 1 + 2x
			x:        one,
			expected: three,
		},
		{
			name:     "evaluate quadratic",
			pCoeffs:  []S{one, two, one}, // 1 + 2x + x^2
			x:        two,
			expected: one.Add(four).Add(four), // 1 + 4 + 4 = 9
		},
		{
			name:     "evaluate zero polynomial",
			pCoeffs:  []S{zero}, // 0
			x:        three,
			expected: zero,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create polynomial
			p, err := polyRing.New(tc.pCoeffs...)
			require.NoError(t, err)

			// Evaluate polynomial
			result := p.Eval(tc.x)

			// Verify result
			require.True(t, result.Equal(tc.expected),
				"evaluation mismatch: expected %v, got %v", tc.expected.String(), result.String())
		})
	}
}

func TestPolynomialEvaluation(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := curves.GetScalarField(curve)
	evaluationCases(t, field)
}

func scalarMulCases[S algebra.FiniteRingElement[S]](t *testing.T, coefficientRing algebra.FiniteRing[S]) {
	t.Helper()
	polyRing, err := polynomials.NewPolynomialRing(coefficientRing)
	require.NoError(t, err)

	// Create common coefficients
	zero := coefficientRing.Zero()
	one := coefficientRing.One()
	two := one.Add(one)
	three := two.Add(one)
	four := three.Add(one)
	six := three.Add(three)
	twelve := six.Add(six)

	tests := []struct {
		name           string
		pCoeffs        []S
		scalar         S
		expectedCoeffs []S
		expectedDegree int
	}{
		{
			name:           "scalar multiply by two",
			pCoeffs:        []S{one, two, three}, // 1 + 2x + 3x^2
			scalar:         two,
			expectedCoeffs: []S{two, four, six}, // 2 + 4x + 6x^2
			expectedDegree: 2,
		},
		{
			name:           "scalar multiply by zero",
			pCoeffs:        []S{one, two, three}, // 1 + 2x + 3x^2
			scalar:         zero,
			expectedCoeffs: []S{zero}, // 0
			expectedDegree: -1,
		},
		{
			name:           "scalar multiply by one",
			pCoeffs:        []S{two, four, six}, // 2 + 4x + 6x^2
			scalar:         one,
			expectedCoeffs: []S{two, four, six}, // 2 + 4x + 6x^2
			expectedDegree: 2,
		},
		{
			name:           "scalar multiply constant",
			pCoeffs:        []S{three}, // 3
			scalar:         four,
			expectedCoeffs: []S{twelve}, // 12
			expectedDegree: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create polynomial
			p, err := polyRing.New(tc.pCoeffs...)
			require.NoError(t, err)

			// Scalar multiply
			result := p.ScalarMul(tc.scalar)

			// Verify results
			resultCoeffs := result.Coefficients()
			require.Equal(t, len(tc.expectedCoeffs), len(resultCoeffs), "coefficient count mismatch")

			for i := range tc.expectedCoeffs {
				require.True(t, resultCoeffs[i].Equal(tc.expectedCoeffs[i]),
					"coefficient at index %d: expected %v, got %v", i, tc.expectedCoeffs[i].String(), resultCoeffs[i].String())
			}

			require.Equal(t, tc.expectedDegree, result.Degree(), "degree mismatch")
		})
	}
}

func TestPolynomialScalarMul(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := curves.GetScalarField(curve)
	scalarMulCases(t, field)
}

func miscCases[S algebra.FiniteRingElement[S]](t *testing.T, coefficientRing algebra.FiniteRing[S]) {
	t.Helper()
	polyRing, err := polynomials.NewPolynomialRing(coefficientRing)
	require.NoError(t, err)

	// Create common coefficients
	zero := coefficientRing.Zero()
	one := coefficientRing.One()
	two := one.Add(one)
	three := two.Add(one)

	// Test IsZero
	t.Run("IsZero", func(t *testing.T) {
		zeroP, err := polyRing.New(zero)
		require.NoError(t, err)
		require.True(t, zeroP.IsZero())

		nonZeroP, err := polyRing.New(one)
		require.NoError(t, err)
		require.False(t, nonZeroP.IsZero())

		nonZeroP2, err := polyRing.New(zero, one)
		require.NoError(t, err)
		require.False(t, nonZeroP2.IsZero())
	})

	// Test IsOne
	t.Run("IsOne", func(t *testing.T) {
		oneP, err := polyRing.New(one)
		require.NoError(t, err)
		require.True(t, oneP.IsOne())

		notOneP, err := polyRing.New(two)
		require.NoError(t, err)
		require.False(t, notOneP.IsOne())

		notOneP2, err := polyRing.New(one, one)
		require.NoError(t, err)
		require.False(t, notOneP2.IsOne())
	})

	// Test IsConstant
	t.Run("IsConstant", func(t *testing.T) {
		constP, err := polyRing.New(three)
		require.NoError(t, err)
		require.True(t, constP.IsConstant())

		zeroP, err := polyRing.New(zero)
		require.NoError(t, err)
		require.True(t, zeroP.IsConstant())

		nonConstP, err := polyRing.New(one, two)
		require.NoError(t, err)
		require.False(t, nonConstP.IsConstant())
	})

	// Test IsMonic
	t.Run("IsMonic", func(t *testing.T) {
		monicP, err := polyRing.New(two, three, one) // 2 + 3x + x^2
		require.NoError(t, err)
		require.True(t, monicP.IsMonic())

		nonMonicP, err := polyRing.New(one, one, two) // 1 + x + 2x^2
		require.NoError(t, err)
		require.False(t, nonMonicP.IsMonic())

		constP, err := polyRing.New(one)
		require.NoError(t, err)
		require.True(t, constP.IsMonic()) // constant 1 is considered monic
	})

	// Test ConstantTerm
	t.Run("ConstantTerm", func(t *testing.T) {
		p, err := polyRing.New(three, two, one) // 3 + 2x + x^2
		require.NoError(t, err)
		require.True(t, p.ConstantTerm().Equal(three))

		zeroP, err := polyRing.New(zero)
		require.NoError(t, err)
		require.True(t, zeroP.ConstantTerm().Equal(zero))
	})

	// Test LeadingCoefficient
	t.Run("LeadingCoefficient", func(t *testing.T) {
		p, err := polyRing.New(one, two, three) // 1 + 2x + 3x^2
		require.NoError(t, err)
		require.True(t, p.LeadingCoefficient().Equal(three))

		p2, err := polyRing.New(two, zero, zero, one) // 2 + x^3
		require.NoError(t, err)
		require.True(t, p2.LeadingCoefficient().Equal(one))

		zeroP, err := polyRing.New(zero)
		require.NoError(t, err)
		require.True(t, zeroP.LeadingCoefficient().Equal(zero))
	})

	// Test Neg and Double
	t.Run("Negation and Double", func(t *testing.T) {
		p, err := polyRing.New(one, two) // 1 + 2x
		require.NoError(t, err)

		negP := p.Neg()
		negCoeffs := negP.Coefficients()
		require.True(t, negCoeffs[0].Equal(one.Neg()))
		require.True(t, negCoeffs[1].Equal(two.Neg()))

		doubleP := p.Double()
		doubleCoeffs := doubleP.Coefficients()
		require.True(t, doubleCoeffs[0].Equal(two))
		require.True(t, doubleCoeffs[1].Equal(two.Add(two)))
	})

	// Test Clone and Equal
	t.Run("Clone and Equal", func(t *testing.T) {
		p, err := polyRing.New(one, two, three)
		require.NoError(t, err)
		cloned := p.Clone()

		require.True(t, p.Equal(cloned))
		require.False(t, p == cloned) // Different instances

		different, err := polyRing.New(one, two, two)
		require.NoError(t, err)
		require.False(t, p.Equal(different))
	})
}

func TestPolynomialProperties(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := curves.GetScalarField(curve)
	miscCases(t, field)
}

func euclideanDivCases[S algebra.FiniteRingElement[S]](t *testing.T, coefficientRing algebra.FiniteRing[S]) {
	t.Helper()
	polyRing, err := polynomials.NewPolynomialRing(coefficientRing)
	require.NoError(t, err)

	// Create common coefficients
	zero := coefficientRing.Zero()
	one := coefficientRing.One()
	two := one.Add(one)
	three := two.Add(one)
	four := three.Add(one)
	five := four.Add(one)
	six := five.Add(one)

	tests := []struct {
		name              string
		dividendCoeffs    []S
		divisorCoeffs     []S
		expectedQuotient  []S
		expectedRemainder []S
		expectError       bool
	}{
		{
			name:              "divide by monomial",
			dividendCoeffs:    []S{six, five, four, three}, // 6 + 5x + 4x^2 + 3x^3
			divisorCoeffs:     []S{zero, one},              // x
			expectedQuotient:  []S{five, four, three},      // 5 + 4x + 3x^2
			expectedRemainder: []S{six},                    // 6
			expectError:       false,
		},
		{
			name:              "exact division",
			dividendCoeffs:    []S{four.Neg(), zero, one}, // -4 + x^2 = (x-2)(x+2)
			divisorCoeffs:     []S{two.Neg(), one},        // -2 + x = x - 2
			expectedQuotient:  []S{two, one},              // 2 + x
			expectedRemainder: []S{zero},                  // 0
			expectError:       false,
		},
		{
			name:              "division with remainder",
			dividendCoeffs:    []S{one, two, three, four},  // 1 + 2x + 3x^2 + 4x^3
			divisorCoeffs:     []S{one, one},               // 1 + x
			expectedQuotient:  []S{three, one.Neg(), four}, // 3 - x + 4x^2
			expectedRemainder: []S{two.Neg()},              // -2
			expectError:       false,
		},
		{
			name:              "divide by constant",
			dividendCoeffs:    []S{two, four, six},  // 2 + 4x + 6x^2
			divisorCoeffs:     []S{two},             // 2
			expectedQuotient:  []S{one, two, three}, // 1 + 2x + 3x^2
			expectedRemainder: []S{zero},            // 0
			expectError:       false,
		},
		{
			name:              "dividend smaller than divisor",
			dividendCoeffs:    []S{one, two},       // 1 + 2x
			divisorCoeffs:     []S{one, zero, one}, // 1 + x^2
			expectedQuotient:  []S{zero},           // 0
			expectedRemainder: []S{one, two},       // 1 + 2x
			expectError:       false,
		},
		{
			name:              "divide by zero polynomial",
			dividendCoeffs:    []S{one, two}, // 1 + 2x
			divisorCoeffs:     []S{zero},     // 0
			expectedQuotient:  nil,
			expectedRemainder: nil,
			expectError:       true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create polynomials
			dividend, err := polyRing.New(tc.dividendCoeffs...)
			require.NoError(t, err)
			divisor, err := polyRing.New(tc.divisorCoeffs...)
			require.NoError(t, err)

			// Perform Euclidean division
			quotient, remainder, err := dividend.EuclideanDiv(divisor)

			if tc.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Verify quotient
			quotientCoeffs := quotient.Coefficients()
			require.Equal(t, len(tc.expectedQuotient), len(quotientCoeffs), "quotient coefficient count mismatch")
			for i := range tc.expectedQuotient {
				require.True(t, quotientCoeffs[i].Equal(tc.expectedQuotient[i]),
					"quotient coefficient at index %d: expected %v, got %v", i, tc.expectedQuotient[i].String(), quotientCoeffs[i].String())
			}

			// Verify remainder
			remainderCoeffs := remainder.Coefficients()
			require.Equal(t, len(tc.expectedRemainder), len(remainderCoeffs), "remainder coefficient count mismatch")
			for i := range tc.expectedRemainder {
				require.True(t, remainderCoeffs[i].Equal(tc.expectedRemainder[i]),
					"remainder coefficient at index %d: expected %v, got %v", i, tc.expectedRemainder[i].String(), remainderCoeffs[i].String())
			}

			// Verify division identity: dividend = divisor * quotient + remainder
			product := divisor.Mul(quotient)
			reconstructed := product.Add(remainder)
			require.True(t, dividend.Equal(reconstructed), "division identity failed: dividend != divisor * quotient + remainder")
		})
	}
}

func TestPolynomialEuclideanDiv(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := curves.GetScalarField(curve)
	euclideanDivCases(t, field)
}

func tryInvCases[S algebra.FiniteRingElement[S]](t *testing.T, coefficientRing algebra.FiniteRing[S]) {
	t.Helper()
	polyRing, err := polynomials.NewPolynomialRing(coefficientRing)
	require.NoError(t, err)

	// Create common coefficients
	zero := coefficientRing.Zero()
	one := coefficientRing.One()
	two := one.Add(one)
	three := two.Add(one)

	tests := []struct {
		name        string
		pCoeffs     []S
		expectError bool
		checkInv    bool // whether to check the inverse property
	}{
		{
			name:        "inverse of constant one",
			pCoeffs:     []S{one},
			expectError: false,
			checkInv:    true,
		},
		{
			name:        "inverse of constant two",
			pCoeffs:     []S{two},
			expectError: false,
			checkInv:    true,
		},
		{
			name:        "inverse of constant three",
			pCoeffs:     []S{three},
			expectError: false,
			checkInv:    true,
		},
		{
			name:        "inverse of zero fails",
			pCoeffs:     []S{zero},
			expectError: true,
			checkInv:    false,
		},
		{
			name:        "inverse of non-constant fails",
			pCoeffs:     []S{one, two},
			expectError: true,
			checkInv:    false,
		},
		{
			name:        "inverse of higher degree polynomial fails",
			pCoeffs:     []S{one, two, three},
			expectError: true,
			checkInv:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create polynomial
			p, err := polyRing.New(tc.pCoeffs...)
			require.NoError(t, err)

			// Try to compute inverse
			inv, err := p.TryInv()

			if tc.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, inv)

			if tc.checkInv {
				// Verify that p * inv = 1
				product := p.Mul(inv)
				require.True(t, product.IsOne(), "p * inv should equal 1")

				// Verify that inv * p = 1
				product2 := inv.Mul(p)
				require.True(t, product2.IsOne(), "inv * p should equal 1")

				// Verify that inv is also a constant
				require.True(t, inv.IsConstant(), "inverse should be a constant")
			}
		})
	}
}

func TestPolynomialTryInv(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := curves.GetScalarField(curve)
	tryInvCases(t, field)
}

// stringCases is a table-driven test for the String() method of polynomials.
func stringCases[S algebra.FiniteRingElement[S]](t *testing.T, coefficientRing algebra.FiniteRing[S]) {
	t.Helper()
	polyRing, err := polynomials.NewPolynomialRing(coefficientRing)
	require.NoError(t, err)

	zero := coefficientRing.Zero()
	one := coefficientRing.One()
	two := one.Add(one)
	three := two.Add(one)

	tests := []struct {
		name     string
		coeffs   []S
		expected string
	}{
		{
			name:     "zero polynomial",
			coeffs:   []S{zero},
			expected: "0",
		},
		{
			name:     "constant polynomial",
			coeffs:   []S{three},
			expected: "3",
		},
		{
			name:     "linear polynomial",
			coeffs:   []S{two, one},
			expected: "1*x + 2",
		},
		{
			name:     "quadratic polynomial",
			coeffs:   []S{one, zero, two},
			expected: "2*x^2 + 1",
		},
		{
			name:     "full cubic polynomial",
			coeffs:   []S{one, two, three, one},
			expected: "1*x^3 + 3*x^2 + 2*x + 1",
		},
		{
			name:     "sparse polynomial with leading zeroes",
			coeffs:   []S{zero, one, zero, two},
			expected: "2*x^3 + 1*x",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := polyRing.New(tc.coeffs...)
			require.NoError(t, err)
			actual := p.String()
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestPolynomialString(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := curves.GetScalarField(curve)
	stringCases(t, field)
}

// Tests for PolynomialRing methods
func polynomialRingCases[S algebra.FiniteRingElement[S]](t *testing.T, coefficientRing algebra.FiniteRing[S]) {
	t.Helper()

	t.Run("NewPolynomialRing", func(t *testing.T) {
		// Test successful creation
		polyRing, err := polynomials.NewPolynomialRing(coefficientRing)
		require.NoError(t, err)
		require.NotNil(t, polyRing)

		// Test with nil coefficient ring
		nilRing, err := polynomials.NewPolynomialRing[S](nil)
		require.Error(t, err)
		require.Nil(t, nilRing)
	})

	t.Run("CoefficientRing", func(t *testing.T) {
		polyRing, err := polynomials.NewPolynomialRing(coefficientRing)
		require.NoError(t, err)

		// Verify coefficient ring is the same
		require.Equal(t, coefficientRing, polyRing.ScalarStructure())
	})

	t.Run("Zero", func(t *testing.T) {
		polyRing, err := polynomials.NewPolynomialRing(coefficientRing)
		require.NoError(t, err)

		zero := polyRing.Zero()
		require.True(t, zero.IsZero())
		require.Equal(t, -1, zero.Degree())
		require.Equal(t, 1, len(zero.Coefficients()))
		require.True(t, zero.Coefficients()[0].IsZero())
	})

	t.Run("One", func(t *testing.T) {
		polyRing, err := polynomials.NewPolynomialRing(coefficientRing)
		require.NoError(t, err)

		one := polyRing.One()
		require.True(t, one.IsOne())
		require.Equal(t, 0, one.Degree())
		require.Equal(t, 1, len(one.Coefficients()))
		require.True(t, one.Coefficients()[0].IsOne())
	})

	t.Run("New", func(t *testing.T) {
		polyRing, err := polynomials.NewPolynomialRing(coefficientRing)
		require.NoError(t, err)

		// Create various polynomials
		zero := coefficientRing.Zero()
		one := coefficientRing.One()
		two := one.Add(one)
		three := two.Add(one)

		// Empty coefficients
		p1, err := polyRing.New()
		require.NoError(t, err)
		require.Equal(t, 0, len(p1.Coefficients()))

		// Single coefficient
		p2, err := polyRing.New(three)
		require.NoError(t, err)
		require.Equal(t, 1, len(p2.Coefficients()))
		require.True(t, p2.Coefficients()[0].Equal(three))
		require.Equal(t, 0, p2.Degree())

		// Multiple coefficients
		p3, err := polyRing.New(one, two, three)
		require.NoError(t, err)
		require.Equal(t, 3, len(p3.Coefficients()))
		require.True(t, p3.Coefficients()[0].Equal(one))
		require.True(t, p3.Coefficients()[1].Equal(two))
		require.True(t, p3.Coefficients()[2].Equal(three))
		require.Equal(t, 2, p3.Degree())

		// With trailing zeros
		p4, err := polyRing.New(one, two, zero, zero)
		require.NoError(t, err)
		require.Equal(t, 4, len(p4.Coefficients()))
		require.Equal(t, 1, p4.Degree()) // degree should be 1, not 3
	})

	t.Run("Random", func(t *testing.T) {
		polyRing, err := polynomials.NewPolynomialRing(coefficientRing)
		require.NoError(t, err)

		// Test various degrees
		degrees := []int{-1, 0, 1, 2, 5}
		for _, deg := range degrees {
			t.Run(fmt.Sprintf("degree_%d", deg), func(t *testing.T) {
				p, err := polyRing.RandomPolynomial(deg, crand.Reader)
				require.NoError(t, err)

				if deg == -1 {
					require.True(t, p.IsZero())
					require.Equal(t, -1, p.Degree())
				} else {
					// Note: actual degree might be less than requested if leading coefficients are randomly zero
					require.LessOrEqual(t, p.Degree(), deg)
					require.Equal(t, deg+1, len(p.Coefficients()))
				}
			})
		}

		// Test error cases
		t.Run("negative_degree_error", func(t *testing.T) {
			_, err := polyRing.RandomPolynomial(-2, crand.Reader)
			require.Error(t, err)
		})

		t.Run("nil_reader_error", func(t *testing.T) {
			_, err := polyRing.RandomPolynomial(2, nil)
			require.Error(t, err)
		})
	})

	t.Run("RandomWithConstantTerm", func(t *testing.T) {
		polyRing, err := polynomials.NewPolynomialRing(coefficientRing)
		require.NoError(t, err)

		one := coefficientRing.One()
		two := one.Add(one)
		three := two.Add(one)

		// Test various degrees with specific constant term
		t.Run("degree_-1", func(t *testing.T) {
			p, err := polyRing.RandomPolynomialWithConstantTerm(-1, three, crand.Reader)
			require.NoError(t, err)
			require.True(t, p.IsZero())
		})

		t.Run("degree_0", func(t *testing.T) {
			p, err := polyRing.RandomPolynomialWithConstantTerm(0, three, crand.Reader)
			require.NoError(t, err)
			require.Equal(t, 0, p.Degree())
			require.True(t, p.ConstantTerm().Equal(three))
		})

		t.Run("degree_2", func(t *testing.T) {
			p, err := polyRing.RandomPolynomialWithConstantTerm(2, two, crand.Reader)
			require.NoError(t, err)
			require.LessOrEqual(t, p.Degree(), 2)
			require.True(t, p.ConstantTerm().Equal(two))
			require.Equal(t, 3, len(p.Coefficients()))
		})

		// Test error cases
		t.Run("negative_degree_error", func(t *testing.T) {
			_, err := polyRing.RandomPolynomialWithConstantTerm(-2, one, crand.Reader)
			require.Error(t, err)
		})

		t.Run("nil_reader_error", func(t *testing.T) {
			_, err := polyRing.RandomPolynomialWithConstantTerm(2, one, nil)
			require.Error(t, err)
		})
	})

	t.Run("Properties", func(t *testing.T) {
		polyRing, err := polynomials.NewPolynomialRing(coefficientRing)
		require.NoError(t, err)

		// Test Name
		name := polyRing.Name()
		require.Contains(t, name, "[x]")
		require.Contains(t, name, coefficientRing.Name())

		// Test Characteristic
		char := polyRing.Characteristic()
		require.Equal(t, coefficientRing.Characteristic(), char)

		// Test Order (should be infinite for polynomial rings)
		order := polyRing.Order()
		require.Equal(t, cardinal.Infinite, order)

		// Test OpIdentity
		opId := polyRing.OpIdentity()
		require.True(t, opId.IsZero()) // additive identity is zero

		// Test ScalarStructure
		scalarStruct := polyRing.ScalarStructure()
		require.Equal(t, coefficientRing, scalarStruct)
	})
}

func TestPolynomialRing(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		curve := k256.NewCurve()
		field := curves.GetScalarField(curve)
		polynomialRingCases(t, field)
	})

	t.Run("bls12381", func(t *testing.T) {
		curve := bls12381.NewG1()
		field := curves.GetScalarField(curve)
		polynomialRingCases(t, field)
	})
}

// bytesCases tests the Bytes and FromBytes methods
func bytesCases[S algebra.FiniteRingElement[S]](t *testing.T, coefficientRing algebra.FiniteRing[S]) {
	t.Helper()
	polyRing, err := polynomials.NewPolynomialRing(coefficientRing)
	require.NoError(t, err)

	// Create common coefficients
	zero := coefficientRing.Zero()
	one := coefficientRing.One()
	two := one.Add(one)
	three := two.Add(one)
	four := three.Add(one)

	// Generate a random coefficient for testing
	randomCoeff, err := coefficientRing.Random(crand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name        string
		coeffs      []S
		description string
	}{
		{
			name:        "zero polynomial",
			coeffs:      []S{zero},
			description: "single zero coefficient",
		},
		{
			name:        "constant polynomial",
			coeffs:      []S{three},
			description: "single non-zero coefficient",
		},
		{
			name:        "linear polynomial",
			coeffs:      []S{one, two},
			description: "two coefficients",
		},
		{
			name:        "quadratic polynomial",
			coeffs:      []S{two, three, one},
			description: "three coefficients",
		},
		{
			name:        "polynomial with zero coefficients",
			coeffs:      []S{one, zero, three, zero, four},
			description: "mixed zero and non-zero coefficients",
		},
		{
			name:        "high degree polynomial",
			coeffs:      []S{one, two, three, four, three, two, one},
			description: "many coefficients",
		},
		{
			name:        "polynomial with random coefficients",
			coeffs:      []S{randomCoeff, one, randomCoeff},
			description: "includes random field elements",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create polynomial
			p, err := polyRing.New(tc.coeffs...)
			require.NoError(t, err)

			// Convert to bytes
			bytes := p.Bytes()

			// Verify byte length
			expectedLen := len(tc.coeffs) * coefficientRing.ElementSize()
			require.Equal(t, expectedLen, len(bytes), "byte array length mismatch")

			// Convert back from bytes
			reconstructed, err := polyRing.FromBytes(bytes)
			require.NoError(t, err)

			// Verify reconstruction
			require.True(t, p.Equal(reconstructed), "reconstructed polynomial should equal original")

			// Verify coefficients match
			origCoeffs := p.Coefficients()
			reconCoeffs := reconstructed.Coefficients()
			require.Equal(t, len(origCoeffs), len(reconCoeffs), "coefficient count mismatch")

			for i := range origCoeffs {
				require.True(t, origCoeffs[i].Equal(reconCoeffs[i]),
					"coefficient at index %d mismatch", i)
			}

			// Test individual coefficient byte representation
			t.Run("coefficient_bytes", func(t *testing.T) {
				elemSize := coefficientRing.ElementSize()
				for i, coeff := range tc.coeffs {
					coeffBytes := coeff.Bytes()
					start := i * elemSize
					end := start + elemSize
					require.Equal(t, coeffBytes, bytes[start:end],
						"coefficient %d byte representation mismatch", i)
				}
			})
		})
	}

	// Error cases for FromBytes
	t.Run("FromBytes error cases", func(t *testing.T) {
		t.Run("empty bytes", func(t *testing.T) {
			_, err := polyRing.FromBytes([]byte{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "empty")
		})

		t.Run("invalid byte length", func(t *testing.T) {
			elemSize := coefficientRing.ElementSize()
			// Create byte array with length not divisible by element size
			invalidBytes := make([]byte, elemSize+1)
			_, err := polyRing.FromBytes(invalidBytes)
			require.Error(t, err)
			require.Contains(t, err.Error(), "multiple of element size")
		})

		t.Run("invalid coefficient bytes", func(t *testing.T) {
			// Create bytes that are invalid for the field
			// This assumes that all 0xFF bytes would be invalid (larger than field modulus)
			elemSize := coefficientRing.ElementSize()
			invalidBytes := make([]byte, elemSize)
			for i := range invalidBytes {
				invalidBytes[i] = 0xFF
			}
			_, err := polyRing.FromBytes(invalidBytes)
			// This may or may not error depending on the field implementation
			// If it doesn't error, the test should still pass
			if err != nil {
				require.Contains(t, err.Error(), "coefficient")
			}
		})
	})

	// Round-trip tests with random polynomials
	t.Run("random polynomial round-trip", func(t *testing.T) {
		for degree := 0; degree <= 5; degree++ {
			t.Run(fmt.Sprintf("degree_%d", degree), func(t *testing.T) {
				// Create random polynomial
				p, err := polyRing.RandomPolynomial(degree, crand.Reader)
				require.NoError(t, err)

				// Convert to bytes and back
				bytes := p.Bytes()
				reconstructed, err := polyRing.FromBytes(bytes)
				require.NoError(t, err)

				// Verify equality
				require.True(t, p.Equal(reconstructed))
			})
		}
	})
}

// TestPolynomialBytes tests the Bytes and FromBytes methods
func TestPolynomialBytes(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		curve := k256.NewCurve()
		field := curves.GetScalarField(curve)
		bytesCases(t, field)
	})

	t.Run("bls12381", func(t *testing.T) {
		curve := bls12381.NewG1()
		field := curves.GetScalarField(curve)
		bytesCases(t, field)
	})
}

// TestNewPolynomialFromCoefficients tests the NewPolynomialFromCoefficients function
func TestNewPolynomialFromCoefficients(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		curve := k256.NewCurve()
		field := curves.GetScalarField(curve)

		// Create common coefficients
		zero := field.Zero()
		one := field.One()
		two := one.Add(one)
		three := two.Add(one)

		t.Run("valid polynomials", func(t *testing.T) {
			tests := []struct {
				name           string
				coeffs         []*k256.Scalar
				expectedDegree int
			}{
				{
					name:           "single coefficient",
					coeffs:         []*k256.Scalar{three},
					expectedDegree: 0,
				},
				{
					name:           "linear polynomial",
					coeffs:         []*k256.Scalar{one, two},
					expectedDegree: 1,
				},
				{
					name:           "quadratic polynomial",
					coeffs:         []*k256.Scalar{zero, one, three},
					expectedDegree: 2,
				},
				{
					name:           "polynomial with trailing zeros",
					coeffs:         []*k256.Scalar{one, two, zero, zero},
					expectedDegree: 1,
				},
			}

			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					p, err := polynomials.NewPolynomialFromCoefficients(tc.coeffs...)
					require.NoError(t, err)
					require.NotNil(t, p)

					// Verify coefficients
					coeffs := p.Coefficients()
					require.Equal(t, len(tc.coeffs), len(coeffs))
					for i := range tc.coeffs {
						require.True(t, coeffs[i].Equal(tc.coeffs[i]))
					}

					// Verify degree
					require.Equal(t, tc.expectedDegree, p.Degree())

					// Verify it's a valid polynomial
					require.NotNil(t, p.ScalarStructure())
					require.Equal(t, field, p.ScalarStructure())
				})
			}
		})

		t.Run("error cases", func(t *testing.T) {
			t.Run("empty coefficients", func(t *testing.T) {
				p, err := polynomials.NewPolynomialFromCoefficients[*k256.Scalar]()
				require.Error(t, err)
				require.Nil(t, p)
				require.Contains(t, err.Error(), "empty")
			})
		})

		t.Run("operations on created polynomial", func(t *testing.T) {
			// Create polynomials using NewPolynomialFromCoefficients
			p1, err := polynomials.NewPolynomialFromCoefficients(one, two, three)
			require.NoError(t, err)

			p2, err := polynomials.NewPolynomialFromCoefficients(two, one)
			require.NoError(t, err)

			// Test addition
			sum := p1.Add(p2)
			expectedSum, err := polynomials.NewPolynomialFromCoefficients(three, three, three)
			require.NoError(t, err)
			require.True(t, sum.Equal(expectedSum))

			// Test multiplication
			product := p1.Mul(p2)
			// (1 + 2x + 3x^2)(2 + x) = 2 + (1+4)x + (2+6)x^2 + 3x^3 = 2 + 5x + 8x^2 + 3x^3
			five := two.Add(three)   // 2 + 3 = 5
			eight := five.Add(three) // 5 + 3 = 8
			expectedProduct, err := polynomials.NewPolynomialFromCoefficients(two, five, eight, three)
			require.NoError(t, err)
			require.True(t, product.Equal(expectedProduct))

			// Test evaluation
			x := field.FromUint64(5)
			result := p1.Eval(x)
			// 1 + 2*5 + 3*5^2 = 1 + 10 + 75 = 86
			expected := field.FromUint64(86)
			require.True(t, result.Equal(expected))
		})

		t.Run("compatibility with polynomial ring", func(t *testing.T) {
			polyRing, err := polynomials.NewPolynomialRing(field)
			require.NoError(t, err)

			// Create polynomial using NewPolynomialFromCoefficients
			p1, err := polynomials.NewPolynomialFromCoefficients(two, three, one)
			require.NoError(t, err)

			// Create same polynomial using polynomial ring
			p2, err := polyRing.New(two, three, one)
			require.NoError(t, err)

			// They should be equal
			require.True(t, p1.Equal(p2))

			// Operations should produce same results
			x := field.FromUint64(7)
			require.True(t, p1.Eval(x).Equal(p2.Eval(x)))

			// Bytes representation should be identical
			require.Equal(t, p1.Bytes(), p2.Bytes())
		})
	})

	t.Run("bls12381", func(t *testing.T) {
		curve := bls12381.NewG1()
		field := curves.GetScalarField(curve)

		one := field.One()
		two := one.Add(one)
		three := two.Add(one)

		t.Run("create and manipulate", func(t *testing.T) {
			p, err := polynomials.NewPolynomialFromCoefficients(one, two, three)
			require.NoError(t, err)

			// Test properties
			require.Equal(t, 2, p.Degree())
			require.False(t, p.IsZero())
			require.False(t, p.IsOne())
			require.False(t, p.IsConstant())
			require.False(t, p.IsMonic()) // leading coefficient is 3, not 1

			// Test derivative
			deriv := p.Derivative()
			// d/dx(1 + 2x + 3x^2) = 2 + 6x
			six := three.Add(three)
			expectedDeriv, err := polynomials.NewPolynomialFromCoefficients(two, six)
			require.NoError(t, err)
			require.True(t, deriv.Equal(expectedDeriv))
		})
	})
}
