package birkhoff_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
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

	xs = append(xs, field.FromUint64(1))
	js = append(js, 3)
	ys = append(ys, poly.Derivative().Derivative().Derivative().Eval(field.FromUint64(1)))

	xs = append(xs, field.FromUint64(2))
	js = append(js, 3)
	ys = append(ys, poly.Derivative().Derivative().Derivative().Derivative().Eval(field.FromUint64(2)))

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
