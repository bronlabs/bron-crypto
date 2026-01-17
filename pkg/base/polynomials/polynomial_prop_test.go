package polynomials_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

func PolynomialGenerator(t *testing.T) *rapid.Generator[*polynomials.Polynomial[*k256.Scalar]] {
	return rapid.Custom(func(t *rapid.T) *polynomials.Polynomial[*k256.Scalar] {
		field := k256.NewScalarField()
		polyRing, err := polynomials.NewPolynomialRing(field)
		require.NoError(t, err)
		degree := rapid.IntRange(0, 10).Draw(t, "degree")
		poly, err := polyRing.RandomPolynomial(degree, pcg.NewRandomised())
		require.NoError(t, err)
		return poly
	})
}

func ScalarGenerator(t *testing.T) *rapid.Generator[*k256.Scalar] {
	return rapid.Custom(func(t *rapid.T) *k256.Scalar {
		field := k256.NewScalarField()
		value := rapid.Uint64().Draw(t, "value")
		scalar := field.FromUint64(value)
		return scalar
	})
}

func TestPolynomialRingProperties(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	polyRing, err := polynomials.NewPolynomialRing(field)
	require.NoError(t, err)
	suite := properties.PolynomialRing(t, polyRing, field, PolynomialGenerator(t), ScalarGenerator(t))
	suite.Check(t)
}
