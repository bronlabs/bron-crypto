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
