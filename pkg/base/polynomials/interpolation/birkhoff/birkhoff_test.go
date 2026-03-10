package birkhoff_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation/birkhoff"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	testHappyPath(t, k256.NewScalarField())
}

func Test_HappyPathInExponent(t *testing.T) {
	t.Parallel()

	testHappyPathInExp(t, k256.NewCurve())
}

// Test_UnmetCriteria fails to uniquely determine a degree-3 polynomial because matrix A(E,X,\phi) is singular.
func Test_UnmetCriteria(t *testing.T) {
	t.Parallel()

	testUnmetCriteria(t, k256.NewScalarField())
}

func Test_HappyPath_BLS12381(t *testing.T) {
	t.Parallel()

	testHappyPath(t, bls12381.NewScalarField())
}

func Test_StandardLagrange(t *testing.T) {
	t.Parallel()

	testStandardLagrange(t, k256.NewScalarField())
}

func Test_StandardLagrange_BLS12381(t *testing.T) {
	t.Parallel()

	testStandardLagrange(t, bls12381.NewScalarField())
}

func Test_SingleNode(t *testing.T) {
	t.Parallel()

	testSingleNode(t, k256.NewScalarField())
}

func Test_HigherDegree(t *testing.T) {
	t.Parallel()

	testHigherDegree(t, k256.NewScalarField())
}

func Test_BuildVandermondeMatrix_NonSquare(t *testing.T) {
	t.Parallel()

	testBuildVandermondeNonSquare(t, k256.NewScalarField())
}

func Test_Interpolate_InputValidation(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	one := field.FromUint64(1)

	t.Run("empty_inputs", func(t *testing.T) {
		t.Parallel()
		_, err := birkhoff.Interpolate([]*k256.Scalar{}, []uint64{}, []*k256.Scalar{})
		require.Error(t, err)
	})
	t.Run("mismatched_xs_js", func(t *testing.T) {
		t.Parallel()
		_, err := birkhoff.Interpolate([]*k256.Scalar{one}, []uint64{0, 1}, []*k256.Scalar{one})
		require.Error(t, err)
	})
	t.Run("mismatched_xs_ys", func(t *testing.T) {
		t.Parallel()
		_, err := birkhoff.Interpolate([]*k256.Scalar{one}, []uint64{0}, []*k256.Scalar{one, one})
		require.Error(t, err)
	})
}

func Test_InterpolateInExponent_InputValidation(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	one := group.ScalarField().FromUint64(1)
	g := group.Generator()

	t.Run("empty_inputs", func(t *testing.T) {
		t.Parallel()
		_, err := birkhoff.InterpolateInExponent([]*k256.Scalar{}, []uint64{}, []*k256.Point{})
		require.Error(t, err)
	})
	t.Run("mismatched_xs_js", func(t *testing.T) {
		t.Parallel()
		_, err := birkhoff.InterpolateInExponent([]*k256.Scalar{one}, []uint64{0, 1}, []*k256.Point{g})
		require.Error(t, err)
	})
	t.Run("mismatched_xs_ys", func(t *testing.T) {
		t.Parallel()
		_, err := birkhoff.InterpolateInExponent([]*k256.Scalar{one}, []uint64{0}, []*k256.Point{g, g})
		require.Error(t, err)
	})
}

func Test_BuildVandermondeMatrix_InputValidation(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	one := field.FromUint64(1)

	t.Run("mismatched_lengths", func(t *testing.T) {
		t.Parallel()
		_, err := birkhoff.BuildVandermondeMatrix([]*k256.Scalar{one}, []uint64{0, 1}, 2)
		require.Error(t, err)
	})
	t.Run("zero_cols", func(t *testing.T) {
		t.Parallel()
		_, err := birkhoff.BuildVandermondeMatrix([]*k256.Scalar{one}, []uint64{0}, 0)
		require.Error(t, err)
	})
	t.Run("negative_cols", func(t *testing.T) {
		t.Parallel()
		_, err := birkhoff.BuildVandermondeMatrix([]*k256.Scalar{one}, []uint64{0}, -1)
		require.Error(t, err)
	})
}

func Test_ShuffledNodes(t *testing.T) {
	t.Parallel()

	testShuffledNodes(t, k256.NewScalarField())
}

func testHappyPath[F algebra.PrimeFieldElement[F]](tb testing.TB, field algebra.PrimeField[F]) {
	tb.Helper()
	prng := pcg.NewRandomised()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(tb, err)

	c0, err := field.Random(prng)
	require.NoError(tb, err)
	c1, err := field.Random(prng)
	require.NoError(tb, err)
	c2, err := field.Random(prng)
	require.NoError(tb, err)
	c3, err := field.Random(prng)
	require.NoError(tb, err)
	poly, err := polyRing.New(c0, c1, c2, c3)
	require.NoError(tb, err)

	xs := []F{}
	js := []uint64{}
	ys := []F{}

	xs = append(xs, field.FromUint64(1))
	js = append(js, 0)
	ys = append(ys, poly.Eval(field.FromUint64(1)))

	xs = append(xs, field.FromUint64(2))
	js = append(js, 0)
	ys = append(ys, poly.Eval(field.FromUint64(2)))

	xs = append(xs, field.FromUint64(2))
	js = append(js, 1)
	ys = append(ys, poly.Derivative().Eval(field.FromUint64(2)))

	xs = append(xs, field.FromUint64(3))
	js = append(js, 1)
	ys = append(ys, poly.Derivative().Eval(field.FromUint64(3)))

	xs = append(xs, field.FromUint64(3))
	js = append(js, 2)
	ys = append(ys, poly.Derivative().Derivative().Eval(field.FromUint64(3)))

	xs = append(xs, field.FromUint64(4))
	js = append(js, 2)
	ys = append(ys, poly.Derivative().Derivative().Eval(field.FromUint64(4)))

	xs = append(xs, field.FromUint64(4))
	js = append(js, 3)
	ys = append(ys, poly.Derivative().Derivative().Derivative().Eval(field.FromUint64(4)))

	interpolatedPoly, err := birkhoff.Interpolate(xs, js, ys)
	require.NoError(tb, err)
	require.True(tb, poly.Equal(interpolatedPoly))
}

func testUnmetCriteria[F algebra.PrimeFieldElement[F]](tb testing.TB, field algebra.PrimeField[F]) {
	tb.Helper()
	prng := pcg.NewRandomised()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(tb, err)

	c0, err := field.Random(prng)
	require.NoError(tb, err)
	c1, err := field.Random(prng)
	require.NoError(tb, err)
	c2, err := field.Random(prng)
	require.NoError(tb, err)
	c3, err := field.Random(prng)
	require.NoError(tb, err)
	poly, err := polyRing.New(c0, c1, c2, c3)
	require.NoError(tb, err)

	xs := []F{}
	js := []uint64{}
	ys := []F{}

	xs = append(xs, field.FromUint64(1))
	js = append(js, 0)
	ys = append(ys, poly.Eval(field.FromUint64(1)))

	xs = append(xs, field.FromUint64(1))
	js = append(js, 1)
	ys = append(ys, poly.Derivative().Eval(field.FromUint64(1)))

	// Nodes (1, j=3) and (2, j=3) give linearly dependent rows since
	// the 3rd derivative of a degree-3 polynomial is constant.
	xs = append(xs, field.FromUint64(1))
	js = append(js, 3)
	ys = append(ys, poly.Derivative().Derivative().Derivative().Eval(field.FromUint64(1)))

	xs = append(xs, field.FromUint64(2))
	js = append(js, 3)
	ys = append(ys, poly.Derivative().Derivative().Derivative().Eval(field.FromUint64(2)))

	_, err = birkhoff.Interpolate(xs, js, ys)
	require.Error(tb, err)
}

func testHappyPathInExp[G algebra.PrimeGroupElement[G, F], F algebra.PrimeFieldElement[F]](tb testing.TB, group algebra.PrimeGroup[G, F]) {
	tb.Helper()

	prng := pcg.NewRandomised()
	field := algebra.StructureMustBeAs[algebra.PrimeField[F]](group.ScalarStructure())
	polyModule, err := polynomials.NewPolynomialModule(group)
	require.NoError(tb, err)

	c0, err := field.Random(prng)
	require.NoError(tb, err)
	c1, err := field.Random(prng)
	require.NoError(tb, err)
	c2, err := field.Random(prng)
	require.NoError(tb, err)
	c3, err := field.Random(prng)
	require.NoError(tb, err)

	g := group.Generator()
	expPoly, err := polyModule.New(
		g.ScalarOp(c0),
		g.ScalarOp(c1),
		g.ScalarOp(c2),
		g.ScalarOp(c3),
	)
	require.NoError(tb, err)

	xs := []F{
		field.FromUint64(1),
		field.FromUint64(2),
		field.FromUint64(2),
		field.FromUint64(3),
		field.FromUint64(3),
		field.FromUint64(4),
		field.FromUint64(4),
	}
	js := []uint64{0, 0, 1, 1, 2, 2, 3}
	ys := []G{
		expPoly.Eval(xs[0]),
		expPoly.Eval(xs[1]),
		expPoly.Derivative().Eval(xs[2]),
		expPoly.Derivative().Eval(xs[3]),
		expPoly.Derivative().Derivative().Eval(xs[4]),
		expPoly.Derivative().Derivative().Eval(xs[5]),
		expPoly.Derivative().Derivative().Derivative().Eval(xs[6]),
	}

	interpolated, err := birkhoff.InterpolateInExponent(xs, js, ys)
	require.NoError(tb, err)
	require.True(tb, expPoly.Equal(interpolated))
}

// testStandardLagrange verifies that Birkhoff interpolation with all j=0
// reduces to standard Lagrange interpolation.
func testStandardLagrange[F algebra.PrimeFieldElement[F]](tb testing.TB, field algebra.PrimeField[F]) {
	tb.Helper()
	prng := pcg.NewRandomised()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(tb, err)

	c0, err := field.Random(prng)
	require.NoError(tb, err)
	c1, err := field.Random(prng)
	require.NoError(tb, err)
	c2, err := field.Random(prng)
	require.NoError(tb, err)
	poly, err := polyRing.New(c0, c1, c2)
	require.NoError(tb, err)

	xs := []F{field.FromUint64(1), field.FromUint64(2), field.FromUint64(3)}
	js := []uint64{0, 0, 0}
	ys := []F{poly.Eval(xs[0]), poly.Eval(xs[1]), poly.Eval(xs[2])}

	interpolatedPoly, err := birkhoff.Interpolate(xs, js, ys)
	require.NoError(tb, err)
	require.True(tb, poly.Equal(interpolatedPoly))
}

// testSingleNode verifies interpolation of a single (x, 0, y) node
// produces the constant polynomial y.
func testSingleNode[F algebra.PrimeFieldElement[F]](tb testing.TB, field algebra.PrimeField[F]) {
	tb.Helper()
	prng := pcg.NewRandomised()

	y, err := field.Random(prng)
	require.NoError(tb, err)

	xs := []F{field.FromUint64(5)}
	js := []uint64{0}
	ys := []F{y}

	poly, err := birkhoff.Interpolate(xs, js, ys)
	require.NoError(tb, err)
	require.Equal(tb, 0, poly.Degree())
	require.True(tb, poly.Coefficients()[0].Equal(y))
}

// testHigherDegree verifies interpolation with a degree-5 polynomial using
// a Tassa-like hierarchical node layout (3 levels with thresholds 2, 4, 6).
func testHigherDegree[F algebra.PrimeFieldElement[F]](tb testing.TB, field algebra.PrimeField[F]) {
	tb.Helper()
	prng := pcg.NewRandomised()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(tb, err)

	coeffs := make([]F, 6)
	for i := range coeffs {
		coeffs[i], err = field.Random(prng)
		require.NoError(tb, err)
	}
	poly, err := polyRing.New(coeffs...)
	require.NoError(tb, err)

	// Level 0 (rank 0): f(1), f(2)
	// Level 1 (rank 2): f''(3), f''(4)
	// Level 2 (rank 4): f''''(5), f''''(6)
	deriv0 := poly
	deriv2 := poly.Derivative().Derivative()
	deriv4 := poly.Derivative().Derivative().Derivative().Derivative()

	xs := []F{
		field.FromUint64(1), field.FromUint64(2),
		field.FromUint64(3), field.FromUint64(4),
		field.FromUint64(5), field.FromUint64(6),
	}
	js := []uint64{0, 0, 2, 2, 4, 4}
	ys := []F{
		deriv0.Eval(xs[0]), deriv0.Eval(xs[1]),
		deriv2.Eval(xs[2]), deriv2.Eval(xs[3]),
		deriv4.Eval(xs[4]), deriv4.Eval(xs[5]),
	}

	interpolatedPoly, err := birkhoff.Interpolate(xs, js, ys)
	require.NoError(tb, err)
	require.True(tb, poly.Equal(interpolatedPoly))
}

// testBuildVandermondeNonSquare verifies BuildVandermondeMatrix with more rows
// than columns, which is how InducedMSP uses it.
func testBuildVandermondeNonSquare[F algebra.PrimeFieldElement[F]](tb testing.TB, field algebra.PrimeField[F]) {
	tb.Helper()

	// 6 shareholders, threshold 4 → 6×4 matrix.
	xs := []F{
		field.FromUint64(1), field.FromUint64(2), field.FromUint64(3),
		field.FromUint64(4), field.FromUint64(5), field.FromUint64(6),
	}
	// Ranks: L0 {1,2,3} rank=0, L1 {4,5,6} rank=2
	js := []uint64{0, 0, 0, 2, 2, 2}
	cols := 4

	m, err := birkhoff.BuildVandermondeMatrix(xs, js, cols)
	require.NoError(tb, err)

	// The matrix should NOT be convertible to a square matrix.
	_, err = m.AsSquare()
	require.Error(tb, err)

	get := func(row, col int) F {
		tb.Helper()
		v, err := m.Get(row, col)
		require.NoError(tb, err)
		return v
	}

	// Row 0: (x=1, j=0) → [Φ(0,1,0), Φ(1,1,0), Φ(2,1,0), Φ(3,1,0)] = [1, 1, 1, 1]
	require.True(tb, get(0, 0).Equal(field.One()))
	require.True(tb, get(0, 1).Equal(field.One()))
	require.True(tb, get(0, 2).Equal(field.One()))
	require.True(tb, get(0, 3).Equal(field.One()))

	// Row 1: (x=2, j=0) → [1, 2, 4, 8]
	require.True(tb, get(1, 0).Equal(field.One()))
	require.True(tb, get(1, 1).Equal(field.FromUint64(2)))
	require.True(tb, get(1, 2).Equal(field.FromUint64(4)))
	require.True(tb, get(1, 3).Equal(field.FromUint64(8)))

	// Row 3: (x=4, j=2) → [Φ(0,4,2), Φ(1,4,2), Φ(2,4,2), Φ(3,4,2)]
	// Φ(t, x, 2) = d²/dx²[x^t] at x=4
	//   t=0: 0, t=1: 0, t=2: 2, t=3: 3·2·4 = 24
	require.True(tb, get(3, 0).Equal(field.Zero()))
	require.True(tb, get(3, 1).Equal(field.Zero()))
	require.True(tb, get(3, 2).Equal(field.FromUint64(2)))
	require.True(tb, get(3, 3).Equal(field.FromUint64(24)))
}

// testShuffledNodes verifies that interpolation produces the same polynomial
// regardless of the order in which nodes are provided.
func testShuffledNodes[F algebra.PrimeFieldElement[F]](tb testing.TB, field algebra.PrimeField[F]) {
	tb.Helper()
	prng := pcg.NewRandomised()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(tb, err)

	c0, err := field.Random(prng)
	require.NoError(tb, err)
	c1, err := field.Random(prng)
	require.NoError(tb, err)
	c2, err := field.Random(prng)
	require.NoError(tb, err)
	poly, err := polyRing.New(c0, c1, c2)
	require.NoError(tb, err)

	// Sorted order.
	xs1 := []F{field.FromUint64(1), field.FromUint64(2), field.FromUint64(3)}
	js1 := []uint64{0, 0, 0}
	ys1 := []F{poly.Eval(xs1[0]), poly.Eval(xs1[1]), poly.Eval(xs1[2])}

	// Reversed order.
	xs2 := []F{field.FromUint64(3), field.FromUint64(1), field.FromUint64(2)}
	js2 := []uint64{0, 0, 0}
	ys2 := []F{poly.Eval(xs2[0]), poly.Eval(xs2[1]), poly.Eval(xs2[2])}

	p1, err := birkhoff.Interpolate(xs1, js1, ys1)
	require.NoError(tb, err)
	p2, err := birkhoff.Interpolate(xs2, js2, ys2)
	require.NoError(tb, err)
	require.True(tb, p1.Equal(p2))
}
