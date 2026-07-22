package lindell17_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/lindell17"
)

func TestDecomposeTwoThirds(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, tc := range []struct {
		name      string
		numerator uint64
	}{
		{name: "first", numerator: 1},
		{name: "second", numerator: 4},
		{name: "third", numerator: 7},
		{name: "fourth", numerator: 10},
		{name: "fifth", numerator: 13},
		{name: "sixth", numerator: 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			x := scalarAtFractionOfOrder(t, field, tc.numerator, 18)
			xPrime, xDoublePrime, err := lindell17.DecomposeTwoThirds(x, pcg.New(1, 2))
			require.NoError(t, err)
			require.True(t, xPrime.Add(xPrime).Add(xPrime).Add(xDoublePrime).Equal(x))
			requireBoundedIntegerLift(t, field, xPrime, xDoublePrime)
			requireInMiddleThird(t, field, xPrime)
			requireInMiddleThird(t, field, xDoublePrime)
		})
	}
}

func TestDecomposeTwoThirdsRejectsNilInputs(t *testing.T) {
	t.Parallel()

	var scalar *k256.Scalar
	_, _, err := lindell17.DecomposeTwoThirds(scalar, pcg.New(1, 2))
	require.ErrorIs(t, err, lindell17.ErrInvalidArgument)

	_, _, err = lindell17.DecomposeTwoThirds(k256.NewScalarField().One(), nil)
	require.ErrorIs(t, err, lindell17.ErrInvalidArgument)
}

func requireBoundedIntegerLift(t *testing.T, field *k256.ScalarField, xPrime, xDoublePrime *k256.Scalar) {
	t.Helper()

	orderNat, err := num.N().FromCardinal(field.Order())
	require.NoError(t, err)
	order := orderNat.Lift()
	xPrimeNat, err := num.N().FromBytes(xPrime.Bytes())
	require.NoError(t, err)
	xDoublePrimeNat, err := num.N().FromBytes(xDoublePrime.Bytes())
	require.NoError(t, err)
	integerLift := xPrimeNat.Lift().Mul(num.Z().FromUint64(3)).Add(xDoublePrimeNat.Lift())

	require.True(t, order.IsLessThanOrEqual(integerLift), "integer lift is below q")
	require.False(t, order.Mul(num.Z().FromUint64(3)).IsLessThanOrEqual(integerLift), "integer lift is at least 3q")
}

func scalarAtFractionOfOrder(t *testing.T, field *k256.ScalarField, numerator, denominator uint64) *k256.Scalar {
	t.Helper()

	order, err := num.N().FromCardinal(field.Order())
	require.NoError(t, err)
	value, _, err := order.Lift().Mul(num.Z().FromUint64(numerator)).EuclideanDivVarTime(num.Z().FromUint64(denominator))
	require.NoError(t, err)
	scalar, err := field.FromWideBytes(value.Bytes())
	require.NoError(t, err)
	return scalar
}

func requireInMiddleThird(t *testing.T, field *k256.ScalarField, scalar *k256.Scalar) {
	t.Helper()

	orderNat, err := num.N().FromCardinal(field.Order())
	require.NoError(t, err)
	order := orderNat.Lift()
	scalarNat, err := num.N().FromBytes(scalar.Bytes())
	require.NoError(t, err)
	threeScalar := scalarNat.Lift().Mul(num.Z().FromUint64(3))
	require.True(t, order.IsLessThanOrEqual(threeScalar), "scalar is below q/3")
	require.False(t, order.Mul(num.Z().FromUint64(2)).IsLessThanOrEqual(threeScalar), "scalar is at least 2q/3")
}
