package polynomials_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/stretchr/testify/require"
)

func TestLiftToExponent(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := curves.GetScalarField(curve)
	g := curve.Generator()

	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	secret, err := field.Random(crand.Reader)
	require.NoError(t, err)
	publicKey := g.ScalarMul(secret)

	p, err := polyRing.RandomPolynomialWithConstantTerm(2, secret, crand.Reader)
	require.NoError(t, err)

	q, err := polynomials.LiftToExponent(p, g)
	require.NoError(t, err)
	require.Equal(t, p.Degree(), q.Degree())
	require.True(t, publicKey.Equal(g.ScalarMul(p.ConstantTerm())))
}

// opCases tests addition of module-valued polynomials for various cases.
func opCases[C algebra.ModuleElement[C, S], S algebra.RingElement[S]](t *testing.T, coeffModule algebra.Module[C, S], g C) {
	t.Helper()
	polyModule, err := polynomials.NewPolynomialModule(coeffModule)
	require.NoError(t, err)

	identity := coeffModule.OpIdentity()
	g2 := g.Op(g)
	g3 := g2.Op(g)
	g4 := g3.Op(g)
	g5 := g4.Op(g)

	tests := []struct {
		name           string
		p1Coeffs       []C
		p2Coeffs       []C
		expectedCoeffs []C
		expectedDegree int
	}{
		{
			name:           "add two module polynomials",
			p1Coeffs:       []C{g, g2, g3},  // g^(1 + 2x + 3x^2)
			p2Coeffs:       []C{g3, g, g},   // g^(3 + x + x^2)
			expectedCoeffs: []C{g4, g3, g4}, // g^(4 + 3x + 4x^2)
			expectedDegree: 2,
		},
		{
			name:           "add with zero polynomial",
			p1Coeffs:       []C{g2, g3},   // g^(2 + 3x)
			p2Coeffs:       []C{identity}, // g^(0)
			expectedCoeffs: []C{g2, g3},   // g^(2 + 3x)
			expectedDegree: 1,
		},
		{
			name:           "add different degrees",
			p1Coeffs:       []C{g},               // g^1
			p2Coeffs:       []C{g4, identity, g}, // g^(4 + 0x + x^2)
			expectedCoeffs: []C{g5, identity, g}, // g^(5 + 0x + x^2)
			expectedDegree: 2,
		},
		{
			name:           "cancel leading term",
			p1Coeffs:       []C{g, g2, g3},         // g^(1 + 2x + 3x^2)
			p2Coeffs:       []C{g2, g, g3.OpInv()}, // g^(2 + x - 3x^2)
			expectedCoeffs: []C{g3, g3},            // g^(3 + 3x)
			expectedDegree: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p1, err := polyModule.New(tc.p1Coeffs...)
			require.NoError(t, err)
			p2, err := polyModule.New(tc.p2Coeffs...)
			require.NoError(t, err)
			sum := p1.Op(p2)

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

func TestModuleValuedPolynomialOp(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	opCases(t, curve, curve.Generator())
}

func TestModuleValuedPolynomialDegree(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()

	polyModule, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)

	identity := curve.OpIdentity()
	g := curve.Generator()
	g2 := g.Op(g)
	g3 := g2.Op(g)
	g4 := g3.Op(g)

	tests := []struct {
		name     string
		coeffs   []*k256.Point
		expected int
	}{
		{
			name:     "identity polynomial",
			coeffs:   []*k256.Point{identity},
			expected: -1,
		},
		{
			name:     "constant polynomial",
			coeffs:   []*k256.Point{g},
			expected: 0,
		},
		{
			name:     "linear polynomial",
			coeffs:   []*k256.Point{g3, g2},
			expected: 1,
		},
		{
			name:     "quadratic polynomial",
			coeffs:   []*k256.Point{g2, identity, g4},
			expected: 2,
		},
		{
			name:     "degree drops after trailing zeros",
			coeffs:   []*k256.Point{g2, g3, identity, identity},
			expected: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := polyModule.New(tc.coeffs...)
			require.NoError(t, err)
			require.Equal(t, tc.expected, p.Degree())
		})
	}
}

// scalarOpCases tests scalar multiplication of module-valued polynomials
func scalarOpCases[C algebra.ModuleElement[C, S], S algebra.RingElement[S]](t *testing.T, coeffModule algebra.Module[C, S], g C, field algebra.Ring[S]) {
	t.Helper()
	polyModule, err := polynomials.NewPolynomialModule(coeffModule)
	require.NoError(t, err)

	// Create scalars
	zero := field.OpIdentity()
	one := field.One()
	two := one.Add(one)
	three := two.Add(one)
	four := three.Add(one)

	// Create module elements
	identity := coeffModule.OpIdentity()
	g2 := g.Op(g)
	g3 := g2.Op(g)
	g4 := g3.Op(g)
	g6 := g3.Op(g3)
	g12 := g6.Op(g6)

	tests := []struct {
		name           string
		pCoeffs        []C
		scalar         S
		expectedCoeffs []C
		expectedDegree int
	}{
		{
			name:           "scalar multiply by two",
			pCoeffs:        []C{g, g2, g3}, // g^(1 + 2x + 3x^2)
			scalar:         two,
			expectedCoeffs: []C{g2, g4, g6}, // g^(2 + 4x + 6x^2)
			expectedDegree: 2,
		},
		{
			name:           "scalar multiply by zero",
			pCoeffs:        []C{g, g2, g3}, // g^(1 + 2x + 3x^2)
			scalar:         zero,
			expectedCoeffs: []C{identity}, // identity polynomial
			expectedDegree: -1,
		},
		{
			name:           "scalar multiply by one",
			pCoeffs:        []C{g2, g4, g6}, // g^(2 + 4x + 6x^2)
			scalar:         one,
			expectedCoeffs: []C{g2, g4, g6}, // g^(2 + 4x + 6x^2)
			expectedDegree: 2,
		},
		{
			name:           "scalar multiply constant polynomial",
			pCoeffs:        []C{g3}, // g^3
			scalar:         four,
			expectedCoeffs: []C{g12}, // g^12
			expectedDegree: 0,
		},
		{
			name:           "scalar multiply with identity coefficients",
			pCoeffs:        []C{g, identity, g2}, // g^(1 + 0x + 2x^2)
			scalar:         three,
			expectedCoeffs: []C{g3, identity, g6}, // g^(3 + 0x + 6x^2)
			expectedDegree: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := polyModule.New(tc.pCoeffs...)
			require.NoError(t, err)
			result := p.ScalarOp(tc.scalar)

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

func TestModuleValuedPolynomialScalarOp(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := curves.GetScalarField(curve)
	scalarOpCases(t, curve, curve.Generator(), field)
}

// evalCases tests evaluation of module-valued polynomials
func evalCases[C algebra.ModuleElement[C, S], S algebra.RingElement[S]](t *testing.T, coeffModule algebra.Module[C, S], g C, field algebra.Ring[S]) {
	t.Helper()
	polyModule, err := polynomials.NewPolynomialModule(coeffModule)
	require.NoError(t, err)

	// Create scalars
	zero := field.OpIdentity()
	one := field.One()
	two := one.Add(one)
	three := two.Add(one)

	// Create module elements
	identity := coeffModule.OpIdentity()
	g2 := g.Op(g)
	g3 := g2.Op(g)
	g4 := g3.Op(g)
	g5 := g4.Op(g)
	g6 := g5.Op(g)
	g7 := g6.Op(g)
	g8 := g7.Op(g)
	g9 := g8.Op(g)
	g10 := g9.Op(g)
	g12 := g10.Op(g2)
	g14 := g12.Op(g2)

	tests := []struct {
		name     string
		pCoeffs  []C
		x        S
		expected C
	}{
		{
			name:     "evaluate constant polynomial",
			pCoeffs:  []C{g3}, // g^3
			x:        two,
			expected: g3, // g^3 (constant doesn't depend on x)
		},
		{
			name:     "evaluate linear at zero",
			pCoeffs:  []C{g, g2}, // g^(1 + 2x)
			x:        zero,
			expected: g, // g^(1 + 2*0) = g^1
		},
		{
			name:     "evaluate linear at one",
			pCoeffs:  []C{g, g2}, // g^(1 + 2x)
			x:        one,
			expected: g3, // g^(1 + 2*1) = g^3
		},
		{
			name:     "evaluate quadratic",
			pCoeffs:  []C{g, g2, g}, // g^(1 + 2x + x^2)
			x:        two,
			expected: g9, // g^(1 + 2*2 + 2^2) = g^(1 + 4 + 4) = g^9
		},
		{
			name:     "evaluate zero polynomial",
			pCoeffs:  []C{identity}, // identity
			x:        three,
			expected: identity, // always identity
		},
		{
			name:     "evaluate cubic polynomial",
			pCoeffs:  []C{g2, identity, g, g}, // g^(2 + 0x + x^2 + x^3)
			x:        two,
			expected: g14, // g^(2 + 0 + 4 + 8) = g^14
		},
		{
			name:     "evaluate at x=3",
			pCoeffs:  []C{g, g, g}, // g^(1 + x + x^2)
			x:        three,
			expected: g4.ScalarOp(three).Op(g), // g^(1 + 3 + 9) = g^13
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := polyModule.New(tc.pCoeffs...)
			require.NoError(t, err)
			result := p.Eval(tc.x)

			require.True(t, result.Equal(tc.expected),
				"evaluation mismatch: expected %v, got %v", tc.expected.String(), result.String())
		})
	}
}

func TestModuleValuedPolynomialEval(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := curves.GetScalarField(curve)
	evalCases(t, curve, curve.Generator(), field)
}

// Test combined operations: evaluation of scaled polynomials
func TestModuleValuedPolynomialCombinedOps(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := curves.GetScalarField(curve)
	g := curve.Generator()

	polyModule, err := polynomials.NewPolynomialModule(curve)
	require.NoError(t, err)

	// Create scalars
	two := field.One().Add(field.One())
	three := two.Add(field.One())

	// Create module elements
	g2 := g.Op(g)
	g3 := g2.Op(g)

	t.Run("evaluate scaled polynomial", func(t *testing.T) {
		// p(x) = g^(1 + 2x)
		p, err := polyModule.New(g, g2)
		require.NoError(t, err)

		// Scale by 3: 3*p(x) = g^(3 + 6x)
		scaled := p.ScalarOp(three)

		// Evaluate at x=2: g^(3 + 6*2) = g^15
		result := scaled.Eval(two)

		// Expected: g^15
		g15 := g3.ScalarOp(two.Add(three)) // g^(3*5) = g^15
		require.True(t, result.Equal(g15))
	})

	t.Run("scale evaluated result", func(t *testing.T) {
		// p(x) = g^(2 + x + x^2)
		p, err := polyModule.New(g2, g, g)
		require.NoError(t, err)

		// Evaluate at x=2: g^(2 + 2 + 4) = g^8
		evalResult := p.Eval(two)

		// Scale by 2: 2*g^8 = g^16
		scaled := evalResult.ScalarOp(two)

		// Expected: g^16
		g16 := g2.ScalarOp(two.Add(two).Add(two).Add(two)) // g^(2*8) = g^16
		require.True(t, scaled.Equal(g16))
	})

	t.Run("multiple scalar operations", func(t *testing.T) {
		// p(x) = g^(1 + x)
		p, err := polyModule.New(g, g)
		require.NoError(t, err)

		// Apply multiple scalars: 2 * 3 * p(x) = 6 * p(x) = g^(6 + 6x)
		result := p.ScalarOp(two).ScalarOp(three)

		// Evaluate at x=1: g^(6 + 6) = g^12
		evalResult := result.Eval(field.One())

		// Expected: g^12
		g12 := g2.ScalarOp(two.Add(two).Add(two)) // g^(2*6) = g^12
		require.True(t, evalResult.Equal(g12))
	})
}
