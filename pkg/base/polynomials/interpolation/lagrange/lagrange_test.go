package lagrange_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation/lagrange"
	"github.com/stretchr/testify/require"
)

func TestBasisAt(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()

	t.Run("single node", func(t *testing.T) {
		// With one node, L_0(x) = 1 for all x
		nodes := []*k256.Scalar{field.FromUint64(5)}
		at := field.FromUint64(10)

		basis, err := lagrange.BasisAt(nodes, at)
		require.NoError(t, err)

		coeffs := basis.Coefficients()
		require.Len(t, coeffs, 1)
		require.True(t, coeffs[0].IsOne())
	})

	t.Run("two nodes evaluated at first node", func(t *testing.T) {
		// L_0(x_0) = 1, L_1(x_0) = 0
		x0 := field.FromUint64(1)
		x1 := field.FromUint64(2)
		nodes := []*k256.Scalar{x0, x1}

		basis, err := lagrange.BasisAt(nodes, x0.Clone())
		require.NoError(t, err)

		coeffs := basis.Coefficients()
		require.Len(t, coeffs, 2)
		require.True(t, coeffs[0].IsOne(), "L_0(x_0) should be 1")
		require.True(t, coeffs[1].IsZero(), "L_1(x_0) should be 0")
	})

	t.Run("two nodes evaluated at second node", func(t *testing.T) {
		// L_0(x_1) = 0, L_1(x_1) = 1
		x0 := field.FromUint64(1)
		x1 := field.FromUint64(2)
		nodes := []*k256.Scalar{x0, x1}

		basis, err := lagrange.BasisAt(nodes, x1.Clone())
		require.NoError(t, err)

		coeffs := basis.Coefficients()
		require.Len(t, coeffs, 2)
		require.True(t, coeffs[0].IsZero(), "L_0(x_1) should be 0")
		require.True(t, coeffs[1].IsOne(), "L_1(x_1) should be 1")
	})

	t.Run("basis coefficients sum to one", func(t *testing.T) {
		// For any point, sum of L_i(at) = 1
		nodes := []*k256.Scalar{
			field.FromUint64(1),
			field.FromUint64(3),
			field.FromUint64(7),
		}
		at := field.FromUint64(5)

		basis, err := lagrange.BasisAt(nodes, at)
		require.NoError(t, err)

		sum := field.Zero()
		for _, coeff := range basis.Coefficients() {
			sum = sum.Add(coeff)
		}
		require.True(t, sum.IsOne(), "sum of basis coefficients should be 1")
	})

	t.Run("three nodes specific values", func(t *testing.T) {
		// nodes: x_0=0, x_1=1, x_2=2, evaluate at x=3
		// L_0(3) = (3-1)(3-2) / (0-1)(0-2) = 2*1 / (-1)(-2) = 2/2 = 1
		// L_1(3) = (3-0)(3-2) / (1-0)(1-2) = 3*1 / 1*(-1) = -3
		// L_2(3) = (3-0)(3-1) / (2-0)(2-1) = 3*2 / 2*1 = 3
		nodes := []*k256.Scalar{
			field.FromUint64(0),
			field.FromUint64(1),
			field.FromUint64(2),
		}
		at := field.FromUint64(3)

		basis, err := lagrange.BasisAt(nodes, at)
		require.NoError(t, err)

		coeffs := basis.Coefficients()
		require.Len(t, coeffs, 3)

		one := field.One()
		negThree := field.FromUint64(3).Neg()
		three := field.FromUint64(3)

		require.True(t, coeffs[0].Equal(one), "L_0(3) should be 1")
		require.True(t, coeffs[1].Equal(negThree), "L_1(3) should be -3")
		require.True(t, coeffs[2].Equal(three), "L_2(3) should be 3")
	})

	t.Run("duplicate nodes causes division by zero", func(t *testing.T) {
		nodes := []*k256.Scalar{
			field.FromUint64(5),
			field.FromUint64(5), // duplicate
		}
		at := field.FromUint64(10)

		_, err := lagrange.BasisAt(nodes, at)
		require.Error(t, err)
	})
}

func TestInterpolateAt(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()

	t.Run("interpolate constant function", func(t *testing.T) {
		// f(x) = 7 for all x
		// Interpolating through points (1,7), (2,7), (3,7) should give 7 at any x
		nodes := []*k256.Scalar{
			field.FromUint64(1),
			field.FromUint64(2),
			field.FromUint64(3),
		}
		seven := field.FromUint64(7)
		values := []*k256.Scalar{seven.Clone(), seven.Clone(), seven.Clone()}

		// Evaluate at x=5
		result, err := lagrange.InterpolateAt(nodes, values, field.FromUint64(5))
		require.NoError(t, err)
		require.True(t, result.Equal(seven))

		// Evaluate at x=100
		result, err = lagrange.InterpolateAt(nodes, values, field.FromUint64(100))
		require.NoError(t, err)
		require.True(t, result.Equal(seven))
	})

	t.Run("interpolate linear function", func(t *testing.T) {
		// f(x) = 2x + 1
		// Points: (0,1), (1,3), (2,5)
		nodes := []*k256.Scalar{
			field.FromUint64(0),
			field.FromUint64(1),
			field.FromUint64(2),
		}
		values := []*k256.Scalar{
			field.FromUint64(1), // f(0) = 1
			field.FromUint64(3), // f(1) = 3
			field.FromUint64(5), // f(2) = 5
		}

		// Evaluate at x=3: f(3) = 2*3 + 1 = 7
		result, err := lagrange.InterpolateAt(nodes, values, field.FromUint64(3))
		require.NoError(t, err)
		require.True(t, result.Equal(field.FromUint64(7)))

		// Evaluate at x=10: f(10) = 2*10 + 1 = 21
		result, err = lagrange.InterpolateAt(nodes, values, field.FromUint64(10))
		require.NoError(t, err)
		require.True(t, result.Equal(field.FromUint64(21)))
	})

	t.Run("interpolate quadratic function", func(t *testing.T) {
		// f(x) = x^2
		// Points: (0,0), (1,1), (2,4), (3,9)
		nodes := []*k256.Scalar{
			field.FromUint64(0),
			field.FromUint64(1),
			field.FromUint64(2),
			field.FromUint64(3),
		}
		values := []*k256.Scalar{
			field.FromUint64(0),
			field.FromUint64(1),
			field.FromUint64(4),
			field.FromUint64(9),
		}

		// Evaluate at x=5: f(5) = 25
		result, err := lagrange.InterpolateAt(nodes, values, field.FromUint64(5))
		require.NoError(t, err)
		require.True(t, result.Equal(field.FromUint64(25)))
	})

	t.Run("interpolation passes through given points", func(t *testing.T) {
		// Arbitrary values
		nodes := []*k256.Scalar{
			field.FromUint64(2),
			field.FromUint64(5),
			field.FromUint64(9),
		}
		values := []*k256.Scalar{
			field.FromUint64(17),
			field.FromUint64(42),
			field.FromUint64(3),
		}

		// Interpolation at each node should return the corresponding value
		for i, node := range nodes {
			result, err := lagrange.InterpolateAt(nodes, values, node.Clone())
			require.NoError(t, err)
			require.True(t, result.Equal(values[i]), "interpolation at node %d should match value", i)
		}
	})

	t.Run("single point interpolation", func(t *testing.T) {
		nodes := []*k256.Scalar{field.FromUint64(3)}
		values := []*k256.Scalar{field.FromUint64(42)}

		// Any evaluation should return the single value
		result, err := lagrange.InterpolateAt(nodes, values, field.FromUint64(100))
		require.NoError(t, err)
		require.True(t, result.Equal(field.FromUint64(42)))
	})

	t.Run("mismatched lengths returns error", func(t *testing.T) {
		nodes := []*k256.Scalar{field.FromUint64(1), field.FromUint64(2)}
		values := []*k256.Scalar{field.FromUint64(1)} // one less

		_, err := lagrange.InterpolateAt(nodes, values, field.FromUint64(3))
		require.Error(t, err)
	})

	t.Run("duplicate nodes returns error", func(t *testing.T) {
		nodes := []*k256.Scalar{field.FromUint64(1), field.FromUint64(1)}
		values := []*k256.Scalar{field.FromUint64(5), field.FromUint64(5)}

		_, err := lagrange.InterpolateAt(nodes, values, field.FromUint64(3))
		require.Error(t, err)
	})
}

func TestInterpolateInExponentAt(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()

	t.Run("interpolate constant in exponent", func(t *testing.T) {
		// All values are the same point: 5G
		// Interpolation should return 5G at any x
		fiveG := g.ScalarOp(field.FromUint64(5))
		nodes := []*k256.Scalar{
			field.FromUint64(1),
			field.FromUint64(2),
			field.FromUint64(3),
		}
		values := []*k256.Point{fiveG.Clone(), fiveG.Clone(), fiveG.Clone()}

		result, err := lagrange.InterpolateInExponentAt(curve, nodes, values, field.FromUint64(10))
		require.NoError(t, err)
		require.True(t, result.Equal(fiveG))
	})

	t.Run("interpolate linear in exponent", func(t *testing.T) {
		// f(x) = (2x+1)G
		// Points: (0, G), (1, 3G), (2, 5G)
		nodes := []*k256.Scalar{
			field.FromUint64(0),
			field.FromUint64(1),
			field.FromUint64(2),
		}
		values := []*k256.Point{
			g.Clone(),                           // f(0) = 1*G
			g.ScalarOp(field.FromUint64(3)),     // f(1) = 3*G
			g.ScalarOp(field.FromUint64(5)),     // f(2) = 5*G
		}

		// Evaluate at x=3: f(3) = (2*3+1)G = 7G
		result, err := lagrange.InterpolateInExponentAt(curve, nodes, values, field.FromUint64(3))
		require.NoError(t, err)
		expected := g.ScalarOp(field.FromUint64(7))
		require.True(t, result.Equal(expected))
	})

	t.Run("interpolation passes through given points", func(t *testing.T) {
		nodes := []*k256.Scalar{
			field.FromUint64(2),
			field.FromUint64(5),
			field.FromUint64(9),
		}
		values := []*k256.Point{
			g.ScalarOp(field.FromUint64(17)),
			g.ScalarOp(field.FromUint64(42)),
			g.ScalarOp(field.FromUint64(3)),
		}

		for i, node := range nodes {
			result, err := lagrange.InterpolateInExponentAt(curve, nodes, values, node.Clone())
			require.NoError(t, err)
			require.True(t, result.Equal(values[i]), "interpolation at node %d should match value", i)
		}
	})

	t.Run("consistency with scalar interpolation", func(t *testing.T) {
		// Interpolating scalars and then multiplying by G should equal
		// interpolating G*scalars directly
		nodes := []*k256.Scalar{
			field.FromUint64(1),
			field.FromUint64(3),
			field.FromUint64(7),
		}
		scalarValues := []*k256.Scalar{
			field.FromUint64(10),
			field.FromUint64(20),
			field.FromUint64(30),
		}
		pointValues := make([]*k256.Point, len(scalarValues))
		for i, s := range scalarValues {
			pointValues[i] = g.ScalarOp(s)
		}

		at := field.FromUint64(5)

		// Scalar interpolation
		scalarResult, err := lagrange.InterpolateAt(nodes, scalarValues, at.Clone())
		require.NoError(t, err)

		// Point interpolation
		pointResult, err := lagrange.InterpolateInExponentAt(curve, nodes, pointValues, at.Clone())
		require.NoError(t, err)

		// scalarResult * G should equal pointResult
		expected := g.ScalarOp(scalarResult)
		require.True(t, pointResult.Equal(expected))
	})

	t.Run("mismatched lengths returns error", func(t *testing.T) {
		nodes := []*k256.Scalar{field.FromUint64(1), field.FromUint64(2)}
		values := []*k256.Point{g.Clone()} // one less

		_, err := lagrange.InterpolateInExponentAt(curve, nodes, values, field.FromUint64(3))
		require.Error(t, err)
	})

	t.Run("nil module returns error", func(t *testing.T) {
		nodes := []*k256.Scalar{field.FromUint64(1)}
		values := []*k256.Point{g.Clone()}

		_, err := lagrange.InterpolateInExponentAt[*k256.Point, *k256.Scalar](nil, nodes, values, field.FromUint64(3))
		require.Error(t, err)
	})

	t.Run("duplicate nodes returns error", func(t *testing.T) {
		nodes := []*k256.Scalar{field.FromUint64(1), field.FromUint64(1)}
		values := []*k256.Point{g.Clone(), g.Clone()}

		_, err := lagrange.InterpolateInExponentAt(curve, nodes, values, field.FromUint64(3))
		require.Error(t, err)
	})
}

func TestInterpolatePolynomialReconstruction(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	t.Run("reconstruct polynomial from evaluations", func(t *testing.T) {
		// Create a polynomial: p(x) = 3 + 2x + x^2
		original, err := polyRing.New(
			field.FromUint64(3),
			field.FromUint64(2),
			field.FromUint64(1),
		)
		require.NoError(t, err)

		// Evaluate at 3 points (degree 2 polynomial needs 3 points)
		nodes := []*k256.Scalar{
			field.FromUint64(0),
			field.FromUint64(1),
			field.FromUint64(2),
		}
		values := make([]*k256.Scalar, len(nodes))
		for i, node := range nodes {
			values[i] = original.Eval(node)
		}

		// Interpolation at any point should match original polynomial evaluation
		testPoints := []*k256.Scalar{
			field.FromUint64(5),
			field.FromUint64(10),
			field.FromUint64(100),
		}
		for _, testPoint := range testPoints {
			interpolated, err := lagrange.InterpolateAt(nodes, values, testPoint.Clone())
			require.NoError(t, err)

			expected := original.Eval(testPoint)
			require.True(t, interpolated.Equal(expected), "interpolation should match polynomial at x=%v", testPoint)
		}
	})
}

func TestSharedSecretReconstruction(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	t.Run("Shamir secret sharing style reconstruction", func(t *testing.T) {
		// Secret is the constant term
		secret := field.FromUint64(42)

		// Create polynomial with secret as constant term: p(x) = 42 + 7x + 3x^2
		poly, err := polyRing.New(
			secret.Clone(),
			field.FromUint64(7),
			field.FromUint64(3),
		)
		require.NoError(t, err)

		// Create shares: (i, p(i)) for i = 1, 2, 3
		nodes := []*k256.Scalar{
			field.FromUint64(1),
			field.FromUint64(2),
			field.FromUint64(3),
		}
		shares := make([]*k256.Scalar, len(nodes))
		for i, node := range nodes {
			shares[i] = poly.Eval(node)
		}

		// Reconstruct secret by interpolating at x=0
		reconstructed, err := lagrange.InterpolateAt(nodes, shares, field.Zero())
		require.NoError(t, err)
		require.True(t, reconstructed.Equal(secret), "reconstructed secret should match original")
	})

	t.Run("threshold reconstruction", func(t *testing.T) {
		// t-of-n threshold: need t points to reconstruct degree t-1 polynomial
		secret := field.FromUint64(12345)
		threshold := 3 // need 3 shares
		totalShares := 5

		// Create degree threshold-1 polynomial
		coeffs := make([]*k256.Scalar, threshold)
		coeffs[0] = secret.Clone()
		for i := 1; i < threshold; i++ {
			coeffs[i] = field.FromUint64(uint64(i * 7)) // deterministic for testing
		}
		poly, err := polyRing.New(coeffs...)
		require.NoError(t, err)

		// Generate all shares
		allNodes := make([]*k256.Scalar, totalShares)
		allShares := make([]*k256.Scalar, totalShares)
		for i := 0; i < totalShares; i++ {
			allNodes[i] = field.FromUint64(uint64(i + 1))
			allShares[i] = poly.Eval(allNodes[i])
		}

		// Reconstruct with exactly threshold shares (first 3)
		reconstructed, err := lagrange.InterpolateAt(allNodes[:threshold], allShares[:threshold], field.Zero())
		require.NoError(t, err)
		require.True(t, reconstructed.Equal(secret))

		// Reconstruct with different threshold shares (last 3)
		reconstructed, err = lagrange.InterpolateAt(allNodes[2:], allShares[2:], field.Zero())
		require.NoError(t, err)
		require.True(t, reconstructed.Equal(secret))

		// Reconstruct with more than threshold shares (all 5)
		reconstructed, err = lagrange.InterpolateAt(allNodes, allShares, field.Zero())
		require.NoError(t, err)
		require.True(t, reconstructed.Equal(secret))
	})
}
