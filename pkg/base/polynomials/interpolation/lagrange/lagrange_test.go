package lagrange_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation/lagrange"
	"github.com/stretchr/testify/require"
)

// lagrangeBasisCases tests the Lagrange basis polynomial L_i computation
func lagrangeBasisCases[S algebra.FieldElement[S]](t *testing.T, field interface {
	algebra.Field[S]
	algebra.FiniteStructure[S]
}) {
	t.Helper()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	zero := field.Zero()
	one := field.One()
	two := one.Add(one)
	three := two.Add(one)
	four := three.Add(one)
	five := four.Add(one)

	tests := []struct {
		name        string
		i           int
		xs          []S
		expectError bool
		checkBasis  bool // whether to verify basis properties
	}{
		{
			name:        "basis polynomial L_0 for two points",
			i:           0,
			xs:          []S{one, two},
			expectError: false,
			checkBasis:  true,
		},
		{
			name:        "basis polynomial L_1 for two points",
			i:           1,
			xs:          []S{one, two},
			expectError: false,
			checkBasis:  true,
		},
		{
			name:        "basis polynomial L_0 for three points",
			i:           0,
			xs:          []S{zero, one, two},
			expectError: false,
			checkBasis:  true,
		},
		{
			name:        "basis polynomial L_1 for three points",
			i:           1,
			xs:          []S{zero, one, two},
			expectError: false,
			checkBasis:  true,
		},
		{
			name:        "basis polynomial L_2 for three points",
			i:           2,
			xs:          []S{zero, one, two},
			expectError: false,
			checkBasis:  true,
		},
		{
			name:        "basis polynomial for four points",
			i:           1,
			xs:          []S{one, two, three, five},
			expectError: false,
			checkBasis:  true,
		},
		{
			name:        "duplicate x values cause error",
			i:           0,
			xs:          []S{one, two, one}, // duplicate x value
			expectError: true,
			checkBasis:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			Li, err := lagrange.NewBasisPolynomial(polyRing, tc.i, tc.xs)

			if tc.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, Li)

			if tc.checkBasis {
				// Verify L_i(x_i) = 1
				yi := Li.Eval(tc.xs[tc.i])
				require.True(t, yi.Equal(one), "L_%d(x_%d) should equal 1, got %v", tc.i, tc.i, yi.String())

				// Verify L_i(x_j) = 0 for j != i
				for j, xj := range tc.xs {
					if j != tc.i {
						yj := Li.Eval(xj)
						require.True(t, yj.IsZero(), "L_%d(x_%d) should equal 0, got %v", tc.i, j, yj.String())
					}
				}

				// Verify degree
				expectedDegree := len(tc.xs) - 1
				require.Equal(t, expectedDegree, Li.Degree(), "L_%d should have degree %d", tc.i, expectedDegree)
			}
		})
	}
}

func TestLagrangeBasis(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		field := k256.NewScalarField()
		lagrangeBasisCases(t, field)
	})

	t.Run("bls12381", func(t *testing.T) {
		field := bls12381.NewScalarField()
		lagrangeBasisCases(t, field)
	})
}

// basisSetCases tests the computation of complete Lagrange basis sets
func basisSetCases[S algebra.FieldElement[S]](t *testing.T, field interface {
	algebra.Field[S]
	algebra.FiniteStructure[S]
}) {
	t.Helper()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	zero := field.Zero()
	one := field.One()
	two := one.Add(one)
	three := two.Add(one)
	four := three.Add(one)

	tests := []struct {
		name        string
		xs          []S
		expectError bool
	}{
		{
			name:        "basis for two points",
			xs:          []S{one, three},
			expectError: false,
		},
		{
			name:        "basis for three points",
			xs:          []S{zero, one, two},
			expectError: false,
		},
		{
			name:        "basis for four points",
			xs:          []S{one, two, three, four},
			expectError: false,
		},
		{
			name:        "empty points",
			xs:          []S{},
			expectError: false,
		},
		{
			name:        "single point",
			xs:          []S{two},
			expectError: false,
		},
		{
			name:        "duplicate points cause error",
			xs:          []S{one, two, two},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			basis, err := lagrange.NewBasis(polyRing, tc.xs)

			if tc.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, len(tc.xs), len(basis))

			// Verify basis properties
			for i, Li := range basis {
				// Check L_i(x_i) = 1
				if i < len(tc.xs) {
					yi := Li.Eval(tc.xs[i])
					require.True(t, yi.Equal(one), "L_%d(x_%d) should equal 1", i, i)
				}

				// Check L_i(x_j) = 0 for j != i
				for j, xj := range tc.xs {
					if j != i {
						yj := Li.Eval(xj)
						require.True(t, yj.IsZero(), "L_%d(x_%d) should equal 0", i, j)
					}
				}
			}

			// Verify partition of unity: sum of all basis polynomials equals 1
			if len(tc.xs) > 0 {
				sum := polyRing.Zero()
				for _, Li := range basis {
					sum = sum.Add(Li)
				}
				// The sum should be the constant polynomial 1
				require.True(t, sum.IsOne(), "sum of basis polynomials should equal 1")
			}
		})
	}
}

func TestBasisSet(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		field := k256.NewScalarField()
		basisSetCases(t, field)
	})

	t.Run("bls12381", func(t *testing.T) {
		field := bls12381.NewScalarField()
		basisSetCases(t, field)
	})
}

func newPoly[S algebra.FieldElement[S]](t testing.TB, polyRing polynomials.PolynomialRing[S], coeffs ...S) polynomials.Polynomial[S] {
	t.Helper()
	poly, err := polyRing.New(coeffs...)
	require.NoError(t, err)
	return poly
}

// interpolationCases tests polynomial interpolation
func interpolationCases[S algebra.FieldElement[S]](t *testing.T, field interface {
	algebra.Field[S]
	algebra.FiniteStructure[S]
}) {
	t.Helper()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	zero := field.Zero()
	one := field.One()
	two := one.Add(one)
	three := two.Add(one)
	four := three.Add(one)
	five := four.Add(one)

	tests := []struct {
		name           string
		xs             []S
		ys             []S
		expectedPoly   polynomials.Polynomial[S]
		expectError    bool
		verifyIdentity bool // whether to verify p(xs[i]) = ys[i]
	}{
		{
			name:           "interpolate constant polynomial",
			xs:             []S{one},
			ys:             []S{three},
			expectedPoly:   newPoly(t, polyRing, three), // f(x) = 3
			expectError:    false,
			verifyIdentity: true,
		},
		{
			name:           "interpolate linear polynomial",
			xs:             []S{zero, one},
			ys:             []S{two, three},
			expectedPoly:   newPoly(t, polyRing, two, one), // f(x) = 2 + x
			expectError:    false,
			verifyIdentity: true,
		},
		{
			name:           "interpolate linear polynomial (different points)",
			xs:             []S{one, two},
			ys:             []S{three, five},
			expectedPoly:   newPoly(t, polyRing, one, two), // f(x) = 1 + 2x
			expectError:    false,
			verifyIdentity: true,
		},
		{
			name:           "interpolate quadratic polynomial",
			xs:             []S{zero, one, two},
			ys:             []S{one, three, five},
			expectedPoly:   newPoly(t, polyRing, one, two, zero), // f(x) = 1 + 2x
			expectError:    false,
			verifyIdentity: true,
		},
		{
			name:           "interpolate quadratic with non-zero coefficient",
			xs:             []S{zero, one, two},
			ys:             []S{one, two, five},
			expectedPoly:   newPoly(t, polyRing, one, zero, one), // f(x) = 1 + x^2
			expectError:    false,
			verifyIdentity: true,
		},
		{
			name:           "mismatched input lengths",
			xs:             []S{one, two},
			ys:             []S{three},
			expectedPoly:   nil,
			expectError:    true,
			verifyIdentity: false,
		},
		{
			name:           "empty inputs",
			xs:             []S{},
			ys:             []S{},
			expectedPoly:   polyRing.Zero(),
			expectError:    false,
			verifyIdentity: false,
		},
		{
			name:           "duplicate x values",
			xs:             []S{one, two, one},
			ys:             []S{three, four, five},
			expectedPoly:   nil,
			expectError:    true,
			verifyIdentity: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			interpolated, err := lagrange.Interpolate(field, tc.xs, tc.ys)

			if tc.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, interpolated)

			// Verify the interpolated polynomial matches expected
			if tc.expectedPoly != nil {
				require.True(t, interpolated.Equal(tc.expectedPoly),
					"expected polynomial %v, got %v", tc.expectedPoly.String(), interpolated.String())
			}

			// Verify interpolation identity: p(xs[i]) = ys[i]
			if tc.verifyIdentity {
				for i := range tc.xs {
					yi := interpolated.Eval(tc.xs[i])
					require.True(t, yi.Equal(tc.ys[i]),
						"p(x_%d) should equal y_%d: expected %v, got %v", i, i, tc.ys[i].String(), yi.String())
				}
			}
		})
	}
}

func TestInterpolation(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		field := k256.NewScalarField()
		interpolationCases(t, field)
	})

	t.Run("bls12381", func(t *testing.T) {
		field := bls12381.NewScalarField()
		interpolationCases(t, field)
	})
}

// Test interpolation of higher degree polynomials
func TestHigherDegreeInterpolation(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	// Test degrees 0 through 5
	for degree := 0; degree <= 5; degree++ {
		t.Run(fmt.Sprintf("degree_%d", degree), func(t *testing.T) {
			// Generate a random polynomial of the given degree
			poly, err := polyRing.RandomPolynomial(degree, crand.Reader)
			require.NoError(t, err)

			// Generate degree+1 distinct evaluation points
			xs := make([]*k256.Scalar, degree+1)
			ys := make([]*k256.Scalar, degree+1)

			for i := 0; i <= degree; i++ {
				xs[i] = field.FromUint64(uint64(i + 1))
				ys[i] = poly.Eval(xs[i])
			}

			// Interpolate
			interpolated, err := lagrange.Interpolate(field, xs, ys)
			require.NoError(t, err)

			// Verify the interpolated polynomial equals the original
			require.True(t, interpolated.Equal(poly),
				"interpolated polynomial should equal original for degree %d", degree)
		})
	}
}

// Test interpolation with random points
func TestRandomPointInterpolation(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	t.Run("random cubic interpolation", func(t *testing.T) {
		// Create a known cubic polynomial: f(x) = 1 + 2x + 3x^2 + 4x^3
		one := field.One()
		two := one.Add(one)
		three := two.Add(one)
		four := three.Add(one)

		poly, err := polyRing.New(one, two, three, four)
		require.NoError(t, err)

		// Generate 4 random distinct x values
		xs := make([]*k256.Scalar, 4)
		ys := make([]*k256.Scalar, 4)

		for i := 0; i < 4; i++ {
			var x *k256.Scalar
			for {
				x, err = field.Random(crand.Reader)
				require.NoError(t, err)

				// Ensure x is distinct from previous values
				distinct := true
				for j := 0; j < i; j++ {
					if x.Equal(xs[j]) {
						distinct = false
						break
					}
				}
				if distinct {
					break
				}
			}
			xs[i] = x
			ys[i] = poly.Eval(x)
		}

		// Interpolate
		interpolated, err := lagrange.Interpolate(field, xs, ys)
		require.NoError(t, err)

		// Verify coefficients match
		require.True(t, interpolated.Equal(poly),
			"interpolated polynomial should match original")
	})
}

// interpolateAtCases tests the InterpolateAt function which evaluates interpolation at a specific point
func interpolateAtCases[S algebra.FieldElement[S]](t *testing.T, field interface {
	algebra.Field[S]
	algebra.FiniteStructure[S]
}) {
	t.Helper()

	zero := field.Zero()
	one := field.One()
	two := one.Add(one)
	three := two.Add(one)
	four := three.Add(one)
	five := four.Add(one)
	six := five.Add(one)
	seven := six.Add(one)
	eight := seven.Add(one)
	nine := eight.Add(one)

	tests := []struct {
		name        string
		nodes       []S
		values      []S
		at          S
		expected    S
		expectError bool
	}{
		{
			name:        "evaluate constant polynomial",
			nodes:       []S{one},
			values:      []S{five},
			at:          three,
			expected:    five, // f(x) = 5, so f(3) = 5
			expectError: false,
		},
		{
			name:        "evaluate linear polynomial at node",
			nodes:       []S{zero, one},
			values:      []S{two, three},
			at:          zero,
			expected:    two, // f(x) = 2 + x, so f(0) = 2
			expectError: false,
		},
		{
			name:        "evaluate linear polynomial at non-node",
			nodes:       []S{zero, one},
			values:      []S{two, three},
			at:          two,
			expected:    four, // f(x) = 2 + x, so f(2) = 4
			expectError: false,
		},
		{
			name:        "evaluate linear polynomial at another node",
			nodes:       []S{one, two},
			values:      []S{three, five},
			at:          two,
			expected:    five, // f(x) = 1 + 2x passes through (2,5)
			expectError: false,
		},
		{
			name:        "evaluate quadratic at node",
			nodes:       []S{zero, one, two},
			values:      []S{one, two, five},
			at:          one,
			expected:    two, // f(x) = 1 + x^2 passes through (1,2)
			expectError: false,
		},
		{
			name:        "evaluate quadratic at non-node",
			nodes:       []S{zero, one, two},
			values:      []S{one, two, five},
			at:          three,
			expected:    one.Add(nine), // f(x) = 1 + x^2, so f(3) = 1 + 9 = 10
			expectError: false,
		},
		{
			name:        "evaluate cubic polynomial",
			nodes:       []S{zero, one, two, three},
			values:      []S{zero, one, eight, three.Mul(nine)}, // f(x) = x^3
			at:          two,
			expected:    eight, // f(2) = 8
			expectError: false,
		},
		{
			name:        "mismatched input lengths",
			nodes:       []S{one, two},
			values:      []S{three},
			at:          four,
			expected:    zero,
			expectError: true,
		},
		{
			name:        "empty inputs",
			nodes:       []S{},
			values:      []S{},
			at:          one,
			expected:    zero,
			expectError: false,
		},
		{
			name:        "duplicate nodes",
			nodes:       []S{one, two, one},
			values:      []S{three, four, five},
			at:          six,
			expected:    zero,
			expectError: true,
		},
		{
			name:        "evaluate at negative x",
			nodes:       []S{one.Neg(), zero, one},
			values:      []S{four, one, two}, // passes through (-1,4), (0,1), (1,2)
			at:          two,
			expected:    seven, // quadratic through these points evaluated at 2
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := lagrange.InterpolateAt(field, tc.nodes, tc.values, tc.at)

			if tc.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.True(t, result.Equal(tc.expected),
				"expected %v, got %v", tc.expected.String(), result.String())
		})
	}
}

func TestInterpolateAt(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		field := k256.NewScalarField()
		interpolateAtCases(t, field)
	})

	t.Run("bls12381", func(t *testing.T) {
		field := bls12381.NewScalarField()
		interpolateAtCases(t, field)
	})
}

// Test InterpolateAt consistency with Interpolate
func TestInterpolateAtConsistency(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()

	// Create test data
	one := field.One()
	two := one.Add(one)
	three := two.Add(one)
	four := three.Add(one)
	five := four.Add(one)

	nodes := []*k256.Scalar{one, two, three, four}
	values := []*k256.Scalar{two, five, five.Add(five), three.Mul(five)} // arbitrary values

	// Interpolate to get the full polynomial
	poly, err := lagrange.Interpolate(field, nodes, values)
	require.NoError(t, err)

	// Test evaluation at various points
	testPoints := []*k256.Scalar{
		field.Zero(),
		one,
		two,
		three,
		four,
		five,
		field.FromUint64(10),
		field.FromUint64(100),
	}

	for _, at := range testPoints {
		t.Run("at_"+at.String(), func(t *testing.T) {
			// Evaluate using InterpolateAt
			directResult, err := lagrange.InterpolateAt(field, nodes, values, at)
			require.NoError(t, err)

			// Evaluate using the polynomial
			polyResult := poly.Eval(at)

			// They should be equal
			require.True(t, directResult.Equal(polyResult),
				"InterpolateAt and polynomial evaluation should match: got %v vs %v",
				directResult.String(), polyResult.String())
		})
	}
}

// Test InterpolateAt with random polynomials
func TestInterpolateAtRandom(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	for degree := 1; degree <= 5; degree++ {
		t.Run(fmt.Sprintf("degree_%d", degree), func(t *testing.T) {
			// Generate a random polynomial
			poly, err := polyRing.RandomPolynomial(degree, crand.Reader)
			require.NoError(t, err)

			// Generate evaluation nodes
			nodes := make([]*k256.Scalar, degree+1)
			values := make([]*k256.Scalar, degree+1)
			for i := 0; i <= degree; i++ {
				nodes[i] = field.FromUint64(uint64(i))
				values[i] = poly.Eval(nodes[i])
			}

			// Test InterpolateAt at random points
			for i := 0; i < 10; i++ {
				at, err := field.Random(crand.Reader)
				require.NoError(t, err)

				// Direct evaluation
				directResult, err := lagrange.InterpolateAt(field, nodes, values, at)
				require.NoError(t, err)

				// Polynomial evaluation
				polyResult := poly.Eval(at)

				require.True(t, directResult.Equal(polyResult),
					"InterpolateAt should match polynomial evaluation")
			}
		})
	}
}

// Benchmark InterpolateAt vs full interpolation
func BenchmarkInterpolateAtVsInterpolate(b *testing.B) {
	field := k256.NewScalarField()

	degrees := []int{5, 10, 20, 50}

	for _, degree := range degrees {
		// Setup nodes and values
		nodes := make([]*k256.Scalar, degree+1)
		values := make([]*k256.Scalar, degree+1)
		for i := 0; i <= degree; i++ {
			nodes[i] = field.FromUint64(uint64(i))
			values[i] = field.FromUint64(uint64(i * i)) // y = x^2 for simplicity
		}

		evalPoint := field.FromUint64(uint64(degree + 10))

		b.Run(fmt.Sprintf("InterpolateAt_degree_%d", degree), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := lagrange.InterpolateAt(field, nodes, values, evalPoint)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("Interpolate+Eval_degree_%d", degree), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				poly, err := lagrange.Interpolate(field, nodes, values)
				if err != nil {
					b.Fatal(err)
				}
				_ = poly.Eval(evalPoint)
			}
		})
	}
}

// interpolateInExponentCases tests InterpolateInExponent function
func interpolateInExponentCases[C algebra.ModuleElement[C, S], S algebra.FieldElement[S]](
	t *testing.T,
	module interface {
		algebra.Module[C, S]
		algebra.FiniteStructure[C]
	},
	field interface {
		algebra.Field[S]
		algebra.FiniteStructure[S]
	},
	g C,
) {
	t.Helper()

	zero := field.Zero()
	one := field.One()
	two := one.Add(one)
	three := two.Add(one)

	// Module elements
	identity := module.OpIdentity()
	g2 := g.Op(g)
	g3 := g2.Op(g)
	g4 := g3.Op(g)
	g5 := g4.Op(g)

	tests := []struct {
		name           string
		nodes          []S
		values         []C
		expectError    bool
		verifyDegree   bool
		expectedDegree int
		evalPoints     []struct {
			x        S
			expected C
		}
	}{
		{
			name:           "constant polynomial in exponent",
			nodes:          []S{one},
			values:         []C{g3},
			expectError:    false,
			verifyDegree:   true,
			expectedDegree: 0,
			evalPoints: []struct {
				x        S
				expected C
			}{
				{zero, g3},
				{one, g3},
				{two, g3},
				{three, g3},
			},
		},
		{
			name:           "linear polynomial in exponent",
			nodes:          []S{zero, one},
			values:         []C{g2, g3},
			expectError:    false,
			verifyDegree:   true,
			expectedDegree: 1,
			evalPoints: []struct {
				x        S
				expected C
			}{
				{zero, g2},  // f(0) = g^2
				{one, g3},   // f(1) = g^3
				{two, g4},   // f(2) = g^(2 + 2*1) = g^4
				{three, g5}, // f(3) = g^(2 + 3*1) = g^5
			},
		},
		{
			name:           "linear polynomial different nodes",
			nodes:          []S{one, two},
			values:         []C{g, g3},
			expectError:    false,
			verifyDegree:   true,
			expectedDegree: 1,
			evalPoints: []struct {
				x        S
				expected C
			}{
				{one, g},          // f(1) = g^1
				{two, g3},         // f(2) = g^3
				{zero, g.OpInv()}, // f(0) = g^(-1) (extrapolated)
				{three, g5},       // f(3) = g^5 (extrapolated)
			},
		},
		{
			name:           "quadratic polynomial in exponent",
			nodes:          []S{zero, one, two},
			values:         []C{g, g2, g5},
			expectError:    false,
			verifyDegree:   true,
			expectedDegree: 2,
			evalPoints: []struct {
				x        S
				expected C
			}{
				{zero, g}, // f(0) = g^1
				{one, g2}, // f(1) = g^2
				{two, g5}, // f(2) = g^5
			},
		},
		{
			name:        "empty inputs",
			nodes:       []S{},
			values:      []C{},
			expectError: true,
		},
		{
			name:        "mismatched lengths",
			nodes:       []S{one, two},
			values:      []C{g},
			expectError: true,
		},
		{
			name:        "duplicate nodes",
			nodes:       []S{one, two, one},
			values:      []C{g, g2, g3},
			expectError: true,
		},
		{
			name:           "identity element in values",
			nodes:          []S{zero, one, two},
			values:         []C{g2, identity, g4},
			expectError:    false,
			verifyDegree:   true,
			expectedDegree: 2,
			evalPoints: []struct {
				x        S
				expected C
			}{
				{zero, g2},      // f(0) = g^2
				{one, identity}, // f(1) = identity
				{two, g4},       // f(2) = g^4
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			poly, err := lagrange.InterpolateInExponent(module, tc.nodes, tc.values)

			if tc.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, poly)

			if tc.verifyDegree {
				require.Equal(t, tc.expectedDegree, poly.Degree(),
					"expected degree %d, got %d", tc.expectedDegree, poly.Degree())
			}

			// Verify evaluation at specific points
			for _, evalPoint := range tc.evalPoints {
				result := poly.Eval(evalPoint.x)
				require.True(t, result.Equal(evalPoint.expected),
					"at x=%v: expected %v, got %v",
					evalPoint.x.String(), evalPoint.expected.String(), result.String())
			}

			// Verify interpolation property: poly(nodes[i]) = values[i]
			for i := range tc.nodes {
				result := poly.Eval(tc.nodes[i])
				require.True(t, result.Equal(tc.values[i]),
					"interpolation property failed at node %d: expected %v, got %v",
					i, tc.values[i].String(), result.String())
			}
		})
	}
}

func TestInterpolateInExponent(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		curve := k256.NewCurve()
		field := k256.NewScalarField()
		g := curve.Generator()
		interpolateInExponentCases(t, curve, field, g)
	})

	t.Run("bls12381_g1", func(t *testing.T) {
		curve := bls12381.NewG1()
		field := bls12381.NewScalarField()
		g := curve.Generator()
		interpolateInExponentCases(t, curve, field, g)
	})
}

// Test InterpolateInExponent consistency with scalar interpolation
func TestInterpolateInExponentConsistency(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()

	one := field.One()
	two := one.Add(one)
	three := two.Add(one)
	four := three.Add(one)

	// Create a polynomial in scalar form
	nodes := []*k256.Scalar{one, two, three}
	scalarValues := []*k256.Scalar{two, four, two.Mul(four)} // 2, 4, 8

	// Create corresponding module values
	moduleValues := make([]*k256.Point, len(scalarValues))
	for i, s := range scalarValues {
		moduleValues[i] = g.ScalarMul(s)
	}

	// Interpolate scalar polynomial
	scalarPoly, err := lagrange.Interpolate(field, nodes, scalarValues)
	require.NoError(t, err)

	// Interpolate in exponent
	modulePoly, err := lagrange.InterpolateInExponent(curve, nodes, moduleValues)
	require.NoError(t, err)

	// Test at various points
	testPoints := []*k256.Scalar{
		field.Zero(),
		one,
		two,
		three,
		four,
		field.FromUint64(10),
	}

	for _, x := range testPoints {
		// Evaluate scalar polynomial and lift to exponent
		scalarResult := scalarPoly.Eval(x)
		expectedModule := g.ScalarMul(scalarResult)

		// Evaluate module polynomial directly
		moduleResult := modulePoly.Eval(x)

		require.True(t, moduleResult.Equal(expectedModule),
			"at x=%v: scalar eval lifted = %v, module eval = %v",
			x.String(), expectedModule.String(), moduleResult.String())
	}
}

// Test InterpolateInExponent with random polynomials
func TestInterpolateInExponentRandom(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	for degree := 1; degree <= 4; degree++ {
		t.Run(fmt.Sprintf("degree_%d", degree), func(t *testing.T) {
			// Generate a random scalar polynomial
			scalarPoly, err := polyRing.RandomPolynomial(degree, crand.Reader)
			require.NoError(t, err)

			// Generate evaluation nodes
			nodes := make([]*k256.Scalar, degree+1)
			moduleValues := make([]*k256.Point, degree+1)

			for i := 0; i <= degree; i++ {
				nodes[i] = field.FromUint64(uint64(i))
				scalarValue := scalarPoly.Eval(nodes[i])
				moduleValues[i] = g.ScalarMul(scalarValue)
			}

			// Interpolate in exponent
			modulePoly, err := lagrange.InterpolateInExponent(curve, nodes, moduleValues)
			require.NoError(t, err)

			// Verify degree
			require.Equal(t, degree, modulePoly.Degree())

			// Test at random points
			for i := 0; i < 5; i++ {
				x, err := field.Random(crand.Reader)
				require.NoError(t, err)

				// Expected: g^(scalarPoly(x))
				scalarResult := scalarPoly.Eval(x)
				expected := g.ScalarMul(scalarResult)

				// Actual
				result := modulePoly.Eval(x)

				require.True(t, result.Equal(expected),
					"evaluation mismatch at random point")
			}
		})
	}
}

// Benchmark InterpolateInExponent
func BenchmarkInterpolateInExponent(b *testing.B) {
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()

	degrees := []int{5, 10, 20, 50}

	for _, degree := range degrees {
		// Setup nodes and values
		nodes := make([]*k256.Scalar, degree+1)
		values := make([]*k256.Point, degree+1)

		for i := 0; i <= degree; i++ {
			nodes[i] = field.FromUint64(uint64(i))
			// Create values as g^(i^2) for variety
			scalar := field.FromUint64(uint64(i * i))
			values[i] = g.ScalarMul(scalar)
		}

		b.Run(fmt.Sprintf("degree_%d", degree), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := lagrange.InterpolateInExponent(curve, nodes, values)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// interpolateInExponentAtCases tests InterpolateInExponentAt function
func interpolateInExponentAtCases[C algebra.ModuleElement[C, S], S algebra.PrimeFieldElement[S]](
	t *testing.T,
	module interface {
		algebra.Module[C, S]
		algebra.FiniteStructure[C]
	},
	field interface {
		algebra.PrimeField[S]
		algebra.FiniteStructure[S]
	},
	g C,
) {
	t.Helper()

	zero := field.Zero()
	one := field.One()
	two := one.Add(one)
	three := two.Add(one)
	four := three.Add(one)
	five := four.Add(one)
	six := five.Add(one)
	seven := six.Add(one)
	eight := seven.Add(one)
	nine := eight.Add(one)
	fifteen := field.FromUint64(15)
	fourty := field.FromUint64(40)
	eightyFive := field.FromUint64(85)

	// Module elements
	identity := module.OpIdentity()
	g2 := g.Op(g)
	g3 := g2.Op(g)
	g4 := g3.Op(g)
	g5 := g4.Op(g)
	g6 := g5.Op(g)
	g7 := g6.Op(g)
	g8 := g7.Op(g)
	g9 := g8.Op(g)
	g10 := g9.Op(g)

	tests := []struct {
		name        string
		nodes       []S
		values      []C
		at          S
		expected    C
		expectError bool
	}{
		{
			name:        "evaluate constant polynomial at point",
			nodes:       []S{one},
			values:      []C{g5},
			at:          three,
			expected:    g5, // constant g^5
			expectError: false,
		},
		{
			name:        "evaluate linear polynomial at node",
			nodes:       []S{zero, one},
			values:      []C{g2, g3},
			at:          zero,
			expected:    g2, // f(0) = g^2
			expectError: false,
		},
		{
			name:        "evaluate linear polynomial at non-node",
			nodes:       []S{zero, one},
			values:      []C{g2, g3},
			at:          two,
			expected:    g4, // f(2) = g^(2 + 2*1) = g^4
			expectError: false,
		},
		{
			name:        "evaluate linear polynomial at another node",
			nodes:       []S{one, two},
			values:      []C{g, g3},
			at:          two,
			expected:    g3, // f(2) = g^3
			expectError: false,
		},
		{
			name:        "evaluate linear polynomial extrapolated",
			nodes:       []S{one, two},
			values:      []C{g, g3},
			at:          three,
			expected:    g5, // f(3) = g^5 (linear extrapolation)
			expectError: false,
		},
		{
			name:        "evaluate quadratic at node",
			nodes:       []S{zero, one, two},
			values:      []C{g, g2, g5},
			at:          one,
			expected:    g2, // f(1) = g^2
			expectError: false,
		},
		{
			name:        "evaluate quadratic at non-node",
			nodes:       []S{zero, one, two},
			values:      []C{g, g2, g5},
			at:          three,
			expected:    g10, // quadratic extrapolation
			expectError: false,
		},
		{
			name:        "evaluate with identity element",
			nodes:       []S{zero, one, two},
			values:      []C{g2, identity, g4},
			at:          one,
			expected:    identity, // f(1) = identity
			expectError: false,
		},
		{
			name:        "evaluate cubic polynomial",
			nodes:       []S{zero, one, two, three},
			values:      []C{identity, g, g8, g3.ScalarOp(nine)}, // f(x) = g^(x^3)
			at:          two,
			expected:    g8, // f(2) = g^8
			expectError: false,
		},
		{
			name:        "mismatched input lengths",
			nodes:       []S{one, two},
			values:      []C{g3},
			at:          four,
			expected:    identity,
			expectError: true,
		},
		{
			name:        "empty inputs",
			nodes:       []S{},
			values:      []C{},
			at:          one,
			expected:    identity,
			expectError: true,
		},
		{
			name:        "duplicate nodes",
			nodes:       []S{one, two, one},
			values:      []C{g, g2, g3},
			at:          six,
			expected:    identity,
			expectError: true,
		},
		{
			name:        "evaluate at negative x",
			nodes:       []S{one.Neg(), zero, one},
			values:      []C{g4, g, g2}, // specific module values
			at:          two,
			expected:    g7, // computed from quadratic through points
			expectError: false,
		},
		{
			name:        "single node evaluation",
			nodes:       []S{five},
			values:      []C{g7},
			at:          zero,
			expected:    g7, // constant function
			expectError: false,
		},
		{
			name:  "evaluate known cubic in exponent",
			nodes: []S{zero, one, two, three},
			values: []C{
				g.ScalarOp(one), // p(0) = 1
				g.ScalarOp(one.Add(one).Add(one).Add(one)), // p(1) = 1 + 1 + 1 + 1 = 4
				g.ScalarOp(fifteen),                        // p(2) = 1 + 2 + 4 + 8 = 15
				g.ScalarOp(fourty),                         // p(3) = 1 + 3 + 9 + 27 = 40
			},
			at:          four,                   // p(4) = 1 + 4 + 16 + 64 = 85
			expected:    g.ScalarOp(eightyFive), // g^85
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := lagrange.InterpolateInExponentAt(module, tc.nodes, tc.values, tc.at)

			if tc.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.True(t, result.Equal(tc.expected),
				"expected %v, got %v", tc.expected.String(), result.String())
		})
	}
}

func TestInterpolateInExponentAt(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		curve := k256.NewCurve()
		field := k256.NewScalarField()
		g := curve.Generator()
		interpolateInExponentAtCases(t, curve, field, g)
	})

	t.Run("bls12381_g1", func(t *testing.T) {
		curve := bls12381.NewG1()
		field := bls12381.NewScalarField()
		g := curve.Generator()
		interpolateInExponentAtCases(t, curve, field, g)
	})
}

// Test InterpolateInExponentAt consistency with InterpolateInExponent
func TestInterpolateInExponentAtConsistency(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()

	one := field.One()
	two := one.Add(one)
	three := two.Add(one)
	four := three.Add(one)
	five := four.Add(one)

	// Create module values
	g2 := g.Op(g)
	g4 := g2.Op(g2)
	g8 := g4.Op(g4)

	nodes := []*k256.Scalar{one, two, three, four}
	values := []*k256.Point{g2, g4, g8, g2.Op(g4)} // arbitrary module values

	// Interpolate to get the full polynomial
	poly, err := lagrange.InterpolateInExponent(curve, nodes, values)
	require.NoError(t, err)

	// Test evaluation at various points
	testPoints := []*k256.Scalar{
		field.Zero(),
		one,
		two,
		three,
		four,
		five,
		field.FromUint64(10),
		field.FromUint64(100),
	}

	for _, at := range testPoints {
		t.Run("at_"+at.String(), func(t *testing.T) {
			// Evaluate using InterpolateInExponentAt
			directResult, err := lagrange.InterpolateInExponentAt(curve, nodes, values, at)
			require.NoError(t, err)

			// Evaluate using the polynomial
			polyResult := poly.Eval(at)

			// They should be equal
			require.True(t, directResult.Equal(polyResult),
				"InterpolateInExponentAt and polynomial evaluation should match: got %v vs %v",
				directResult.String(), polyResult.String())
		})
	}
}

// Test InterpolateInExponentAt with random polynomials
func TestInterpolateInExponentAtRandom(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	for degree := 1; degree <= 5; degree++ {
		t.Run(fmt.Sprintf("degree_%d", degree), func(t *testing.T) {
			// Generate a random polynomial
			poly, err := polyRing.RandomPolynomial(degree, crand.Reader)
			require.NoError(t, err)

			// Generate evaluation nodes and module values
			nodes := make([]*k256.Scalar, degree+1)
			values := make([]*k256.Point, degree+1)
			for i := 0; i <= degree; i++ {
				nodes[i] = field.FromUint64(uint64(i))
				scalarValue := poly.Eval(nodes[i])
				values[i] = g.ScalarMul(scalarValue)
			}

			// Test InterpolateInExponentAt at random points
			for i := 0; i < 10; i++ {
				at, err := field.Random(crand.Reader)
				require.NoError(t, err)

				// Direct evaluation
				directResult, err := lagrange.InterpolateInExponentAt(curve, nodes, values, at)
				require.NoError(t, err)

				// Expected: g^(poly(at))
				scalarResult := poly.Eval(at)
				expected := g.ScalarMul(scalarResult)

				require.True(t, directResult.Equal(expected),
					"InterpolateInExponentAt should match expected value")
			}
		})
	}
}

// Test InterpolateInExponentAt consistency with InterpolateAt
func TestInterpolateInExponentAtVsInterpolateAt(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()

	one := field.One()
	two := one.Add(one)
	three := two.Add(one)
	four := three.Add(one)

	// Create a polynomial in scalar form
	nodes := []*k256.Scalar{one, two, three}
	scalarValues := []*k256.Scalar{two, four, two.Mul(four)} // 2, 4, 8

	// Create corresponding module values
	moduleValues := make([]*k256.Point, len(scalarValues))
	for i, s := range scalarValues {
		moduleValues[i] = g.ScalarMul(s)
	}

	// Test at various points
	testPoints := []*k256.Scalar{
		field.Zero(),
		one,
		two,
		three,
		four,
		field.FromUint64(10),
	}

	for _, at := range testPoints {
		t.Run("at_"+at.String(), func(t *testing.T) {
			// Evaluate scalar interpolation
			scalarResult, err := lagrange.InterpolateAt(field, nodes, scalarValues, at)
			require.NoError(t, err)

			// Lift to module
			expectedModule := g.ScalarMul(scalarResult)

			// Evaluate module interpolation directly
			moduleResult, err := lagrange.InterpolateInExponentAt(curve, nodes, moduleValues, at)
			require.NoError(t, err)

			require.True(t, moduleResult.Equal(expectedModule),
				"at x=%v: scalar interpolation lifted = %v, module interpolation = %v",
				at.String(), expectedModule.String(), moduleResult.String())
		})
	}
}

// Benchmark InterpolateInExponentAt vs full interpolation
func BenchmarkInterpolateInExponentAtVsInterpolateInExponent(b *testing.B) {
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()

	degrees := []int{5, 10, 20, 50}

	for _, degree := range degrees {
		// Setup nodes and values
		nodes := make([]*k256.Scalar, degree+1)
		values := make([]*k256.Point, degree+1)

		for i := 0; i <= degree; i++ {
			nodes[i] = field.FromUint64(uint64(i))
			// Create values as g^(i^2) for variety
			scalar := field.FromUint64(uint64(i * i))
			values[i] = g.ScalarMul(scalar)
		}

		evalPoint := field.FromUint64(uint64(degree + 10))

		b.Run(fmt.Sprintf("InterpolateInExponentAt_degree_%d", degree), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := lagrange.InterpolateInExponentAt(curve, nodes, values, evalPoint)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("InterpolateInExponent+Eval_degree_%d", degree), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				poly, err := lagrange.InterpolateInExponent(curve, nodes, values)
				if err != nil {
					b.Fatal(err)
				}
				_ = poly.Eval(evalPoint)
			}
		})
	}
}
