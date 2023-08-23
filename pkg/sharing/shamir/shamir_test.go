package shamir_test

import (
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/sharing/shamir"
)

func TestShamirSplitInvalidArgs(t *testing.T) {
	curve := edwards25519.New()
	_, err := shamir.NewDealer(0, 0, curve)
	require.NotNil(t, err)
	_, err = shamir.NewDealer(3, 2, curve)
	require.NotNil(t, err)
	_, err = shamir.NewDealer(1, 10, curve)
	require.NotNil(t, err)
	scheme, err := shamir.NewDealer(2, 3, curve)
	require.Nil(t, err)
	require.NotNil(t, scheme)
}

func TestShamirCombineNoShares(t *testing.T) {
	curve := edwards25519.New()
	scheme, err := shamir.NewDealer(2, 3, curve)
	require.Nil(t, err)
	require.NotNil(t, scheme)
	_, err = scheme.Combine()
	require.Error(t, err)
}

func TestShamirCombineDuplicateShare(t *testing.T) {
	curve := edwards25519.New()
	scheme, err := shamir.NewDealer(2, 3, curve)
	require.Nil(t, err)
	require.NotNil(t, scheme)
	_, err = scheme.Combine([]*shamir.Share{
		{
			Id:    1,
			Value: curve.Scalar().New(3),
		},
		{
			Id:    1,
			Value: curve.Scalar().New(3),
		},
	}...)
	require.NotNil(t, err)
}

func TestShamirCombineBadIdentifier(t *testing.T) {
	curve := edwards25519.New()
	scheme, err := shamir.NewDealer(2, 3, curve)
	require.Nil(t, err)
	require.NotNil(t, scheme)
	shares := []*shamir.Share{
		{
			Id:    0,
			Value: curve.Scalar().New(3),
		},
		{
			Id:    2,
			Value: curve.Scalar().New(3),
		},
	}
	_, err = scheme.Combine(shares...)
	require.NotNil(t, err)
	shares[0] = &shamir.Share{
		Id:    4,
		Value: curve.Scalar().New(3),
	}
	_, err = scheme.Combine(shares...)
	require.NotNil(t, err)
}

func TestShamirCombineSingle(t *testing.T) {
	curve := edwards25519.New()
	scheme, err := shamir.NewDealer(2, 3, curve)
	require.Nil(t, err)
	require.NotNil(t, scheme)

	shares, err := scheme.Split(curve.Scalar().Hash([]byte("test")), crand.Reader)
	require.Nil(t, err)
	require.NotNil(t, shares)
	secret, err := scheme.Combine(shares...)
	require.Nil(t, err)
	require.Equal(t, secret, curve.Scalar().Hash([]byte("test")))
}

// Test ComputeL function to compute Lagrange coefficients.
func TestShamirComputeL(t *testing.T) {
	curve := edwards25519.New()
	scheme, err := shamir.NewDealer(2, 2, curve)
	require.Nil(t, err)
	require.NotNil(t, scheme)
	secret := curve.Scalar().Hash([]byte("test"))
	shares, err := scheme.Split(secret, crand.Reader)
	require.Nil(t, err)
	require.NotNil(t, shares)
	identities := make([]int, len(shares))
	for i, xi := range shares {
		identities[i] = xi.Id
	}
	lCoeffs, err := scheme.LagrangeCoefficients(identities)
	require.Nil(t, err)
	require.NotNil(t, lCoeffs)
	require.Len(t, lCoeffs, len(identities))
	fmt.Println(identities)
	fmt.Println(lCoeffs)

	// Checking we can reconstruct the same secret using Lagrange coefficients.
	result := curve.Scalar()
	for _, r := range shares {
		result = result.Add(r.Value.Mul(lCoeffs[r.Id]))
	}
	require.Equal(t, result.Bytes(), secret.Bytes())
}

func TestShamirAllCombinations(t *testing.T) {
	curve := edwards25519.New()
	scheme, err := shamir.NewDealer(3, 5, curve)
	require.Nil(t, err)
	require.NotNil(t, scheme)

	secret := curve.Scalar().Hash([]byte("test"))
	shares, err := scheme.Split(secret, crand.Reader)
	require.Nil(t, err)
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
				require.Nil(t, err)
				require.NotNil(t, rSecret)
				require.Equal(t, rSecret.Cmp(secret), 0)
			}
		}
	}
}

func TestAdditiveAllCombinations(t *testing.T) {
	t.Parallel()
	curve := edwards25519.New()
	scheme, err := shamir.NewDealer(3, 5, curve)
	require.Nil(t, err)
	require.NotNil(t, scheme)

	secret := curve.Scalar().Hash([]byte("test"))
	shares, err := scheme.Split(secret, crand.Reader)
	require.Nil(t, err)
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

				iAdditive, err := shares[i].ToAdditive([]int{shares[i].Id, shares[j].Id, shares[k].Id})
				require.NoError(t, err)
				jAdditive, err := shares[j].ToAdditive([]int{shares[i].Id, shares[j].Id, shares[k].Id})
				require.NoError(t, err)
				kAdditive, err := shares[k].ToAdditive([]int{shares[i].Id, shares[j].Id, shares[k].Id})
				require.NoError(t, err)

				rSecret := iAdditive.Add(jAdditive.Add(kAdditive))
				require.NotNil(t, rSecret)
				require.Equal(t, rSecret.Cmp(secret), 0)
			}
		}
	}
}

// Ensures that Share's un/marshal successfully.
func TestMarshalJsonRoundTrip(t *testing.T) {
	curve := edwards25519.New()
	shares := []shamir.Share{
		{Id: 0, Value: curve.Scalar().New(300)},
		{Id: 2, Value: curve.Scalar().New(300000)},
		{Id: 20, Value: curve.Scalar().New(12812798)},
		{Id: 31, Value: curve.Scalar().New(17)},
		{Id: 57, Value: curve.Scalar().New(5066680)},
		{Id: 128, Value: curve.Scalar().New(3005)},
		{Id: 19, Value: curve.Scalar().New(317)},
		{Id: 7, Value: curve.Scalar().New(323)},
		{Id: 222, Value: curve.Scalar().New(1).Neg()},
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
