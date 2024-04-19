package shamir_test

import (
	crand "crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

func TestShamirSplitInvalidArgs(t *testing.T) {
	curve := edwards25519.NewCurve()
	_, err := shamir.NewDealer(0, 0, curve)
	require.Error(t, err)
	_, err = shamir.NewDealer(3, 2, curve)
	require.Error(t, err)
	_, err = shamir.NewDealer(1, 10, curve)
	require.Error(t, err)
	scheme, err := shamir.NewDealer(2, 3, curve)
	require.NoError(t, err)
	require.NotNil(t, scheme)
}

func TestShamirCombineNoShares(t *testing.T) {
	curve := edwards25519.NewCurve()
	scheme, err := shamir.NewDealer(2, 3, curve)
	require.NoError(t, err)
	require.NotNil(t, scheme)
	_, err = scheme.Combine()
	require.Error(t, err)
}

func TestShamirCombineDuplicateShare(t *testing.T) {
	curve := edwards25519.NewCurve()
	scheme, err := shamir.NewDealer(2, 3, curve)
	require.NoError(t, err)
	require.NotNil(t, scheme)
	_, err = scheme.Combine([]*shamir.Share{
		{
			Id:    1,
			Value: curve.ScalarField().New(3),
		},
		{
			Id:    1,
			Value: curve.ScalarField().New(3),
		},
	}...)
	require.Error(t, err)
}

func TestShamirCombineBadIdentifier(t *testing.T) {
	curve := edwards25519.NewCurve()
	scheme, err := shamir.NewDealer(2, 3, curve)
	require.NoError(t, err)
	require.NotNil(t, scheme)
	shares := []*shamir.Share{
		{
			Id:    0,
			Value: curve.ScalarField().New(3),
		},
		{
			Id:    2,
			Value: curve.ScalarField().New(3),
		},
	}
	_, err = scheme.Combine(shares...)
	require.Error(t, err)
	shares[0] = &shamir.Share{
		Id:    4,
		Value: curve.ScalarField().New(3),
	}
	_, err = scheme.Combine(shares...)
	require.Error(t, err)
}

func TestShamirCombineSingle(t *testing.T) {
	curve := edwards25519.NewCurve()
	scheme, err := shamir.NewDealer(2, 3, curve)
	require.NoError(t, err)
	require.NotNil(t, scheme)

	randomScalar, err := curve.ScalarField().Hash([]byte("test"))
	require.NoError(t, err)
	shares, err := scheme.Split(randomScalar, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, shares)
	secret, err := scheme.Combine(shares...)
	require.NoError(t, err)
	require.Equal(t, secret, randomScalar)
}

// Test ComputeL function to compute Lagrange coefficients.
func TestShamirComputeL(t *testing.T) {
	curve := edwards25519.NewCurve()
	scheme, err := shamir.NewDealer(2, 2, curve)
	require.NoError(t, err)
	require.NotNil(t, scheme)
	secret, err := curve.ScalarField().Hash([]byte("test"))
	require.NoError(t, err)
	shares, err := scheme.Split(secret, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, shares)
	identities := make([]uint, len(shares))
	for i, xi := range shares {
		identities[i] = (xi.Id)
	}
	lCoeffs, err := scheme.LagrangeCoefficients(identities)
	require.NoError(t, err)
	require.NotNil(t, lCoeffs)
	require.Len(t, lCoeffs, len(identities))

	// Checking we can reconstruct the same secret using Lagrange coefficients.
	result := curve.Scalar()
	for _, r := range shares {
		result = result.Add(r.Value.Mul(lCoeffs[r.Id]))
	}
	require.Equal(t, result.Bytes(), secret.Bytes())
}

func TestShamirAllCombinations(t *testing.T) {
	curve := edwards25519.NewCurve()
	scheme, err := shamir.NewDealer(3, 5, curve)
	require.NoError(t, err)
	require.NotNil(t, scheme)

	secret, err := curve.ScalarField().Hash([]byte("test"))
	require.NoError(t, err)
	shares, err := scheme.Split(secret, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, shares)
	// There are 5*4*3 possible combinations
	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			if i == j {
				continue
			}
			for k := 0; k < 5; k++ {
				if i == k || j == k {
					continue
				}

				rSecret, err := scheme.Combine(shares[i], shares[j], shares[k])
				require.NoError(t, err)
				require.NotNil(t, rSecret)
				require.Equal(t, 0, int(rSecret.Cmp(secret)))
			}
		}
	}
}

func TestAdditiveAllCombinations(t *testing.T) {
	t.Parallel()
	curve := edwards25519.NewCurve()
	scheme, err := shamir.NewDealer(3, 5, curve)
	require.NoError(t, err)
	require.NotNil(t, scheme)

	secret, err := curve.ScalarField().Hash([]byte("test"))
	require.NoError(t, err)
	shares, err := scheme.Split(secret, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, shares)
	// There are 5*4*3 possible combinations
	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			if i == j {
				continue
			}
			for k := 0; k < 5; k++ {
				if i == k || j == k {
					continue
				}

				iAdditive, err := shares[i].ToAdditive([]uint{shares[i].Id, shares[j].Id, shares[k].Id})
				require.NoError(t, err)
				jAdditive, err := shares[j].ToAdditive([]uint{shares[i].Id, shares[j].Id, shares[k].Id})
				require.NoError(t, err)
				kAdditive, err := shares[k].ToAdditive([]uint{shares[i].Id, shares[j].Id, shares[k].Id})
				require.NoError(t, err)

				rSecret := iAdditive.Add(jAdditive.Add(kAdditive))
				require.NotNil(t, rSecret)
				require.Equal(t, 0, int(rSecret.Cmp(secret)))
			}
		}
	}
}

// Ensures that Share's un/marshal successfully.
func TestMarshalJsonRoundTrip(t *testing.T) {
	curve := edwards25519.NewCurve()
	shares := []shamir.Share{
		{Id: 0, Value: curve.ScalarField().New(300)},
		{Id: 2, Value: curve.ScalarField().New(300000)},
		{Id: 20, Value: curve.ScalarField().New(12812798)},
		{Id: 31, Value: curve.ScalarField().New(17)},
		{Id: 57, Value: curve.ScalarField().New(5066680)},
		{Id: 128, Value: curve.ScalarField().New(3005)},
		{Id: 19, Value: curve.ScalarField().New(317)},
		{Id: 7, Value: curve.ScalarField().New(323)},
		{Id: 222, Value: curve.ScalarField().New(1).Neg()},
	}
	// Run all the tests!
	for _, in := range shares {
		input, err := json.Marshal(in)
		require.NoError(t, err)
		require.NotNil(t, input)

		// Unmarshal and test
		var out shamir.Share
		out.Value = curve.Scalar()
		err = json.Unmarshal(input, &out)
		require.NoError(t, err)
		require.Equal(t, in.Id, out.Id)
		require.Equal(t, in.Value, out.Value)
	}
}
