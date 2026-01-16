package polynomials_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
)

func TestPolynomialEuclideanDiv(t *testing.T) {
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	zero := field.Zero()

	dividend, err := polyRing.New(one.Clone(), one.Clone(), one.Clone()) // x^2 + x + 1
	require.NoError(t, err)
	divisor, err := polyRing.New(one.Clone(), one.Clone()) // x + 1
	require.NoError(t, err)

	quot, rem, err := dividend.EuclideanDiv(divisor)
	require.NoError(t, err)

	expectedQuot, err := polyRing.New(zero.Clone(), one.Clone()) // x
	require.NoError(t, err)
	expectedRem, err := polyRing.New(one.Clone()) // 1
	require.NoError(t, err)

	require.True(t, quot.Equal(expectedQuot))
	require.True(t, rem.Equal(expectedRem))
}

func TestPolynomialEuclideanDivDegreeLess(t *testing.T) {
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	zero := field.Zero()

	dividend, err := polyRing.New(one.Clone(), one.Clone()) // x + 1
	require.NoError(t, err)
	divisor, err := polyRing.New(one.Clone(), one.Clone(), one.Clone()) // x^2 + x + 1
	require.NoError(t, err)

	quot, rem, err := dividend.EuclideanDiv(divisor)
	require.NoError(t, err)

	expectedQuot, err := polyRing.New(zero.Clone())
	require.NoError(t, err)

	require.True(t, quot.Equal(expectedQuot))
	require.True(t, rem.Equal(dividend))
}

func TestPolynomialEuclideanDivByZero(t *testing.T) {
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)

	one := field.One()
	dividend, err := polyRing.New(one.Clone(), one.Clone())
	require.NoError(t, err)

	_, _, err = dividend.EuclideanDiv(polyRing.Zero())
	require.Error(t, err)
}
