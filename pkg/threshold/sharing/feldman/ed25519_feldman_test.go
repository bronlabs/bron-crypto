package feldman_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/feldman"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

var testCurve = edwards25519.New()

func TestEd25519FeldmanSplitInvalidArgs(t *testing.T) {
	_, err := feldman.NewDealer(0, 0, testCurve)
	require.NotNil(t, err)
	_, err = feldman.NewDealer(3, 2, testCurve)
	require.NotNil(t, err)
	_, err = feldman.NewDealer(1, 10, testCurve)
	require.NotNil(t, err)
	scheme, err := feldman.NewDealer(2, 3, testCurve)
	require.Nil(t, err)
	require.NotNil(t, scheme)
}

func TestEd25519FeldmanCombineNoShares(t *testing.T) {
	scheme, err := feldman.NewDealer(2, 3, testCurve)
	require.Nil(t, err)
	require.NotNil(t, scheme)
	_, err = scheme.Combine()
	require.NotNil(t, err)
}

func TestEd25519FeldmanCombineDuplicateShare(t *testing.T) {
	scheme, err := feldman.NewDealer(2, 3, testCurve)
	require.Nil(t, err)
	require.NotNil(t, scheme)
	_, err = scheme.Combine([]*shamir.Share{
		{
			Id:    1,
			Value: testCurve.Scalar().New(3),
		},
		{
			Id:    1,
			Value: testCurve.Scalar().New(3),
		},
	}...)
	require.NotNil(t, err)
}

func TestEd25519FeldmanCombineBadIdentifier(t *testing.T) {
	scheme, err := feldman.NewDealer(2, 3, testCurve)
	require.Nil(t, err)
	require.NotNil(t, scheme)
	shares := []*shamir.Share{
		{
			Id:    0,
			Value: testCurve.Scalar().New(3),
		},
		{
			Id:    2,
			Value: testCurve.Scalar().New(3),
		},
	}
	_, err = scheme.Combine(shares...)
	require.NotNil(t, err)
	shares[0] = &shamir.Share{
		Id:    4,
		Value: testCurve.Scalar().New(3),
	}
	_, err = scheme.Combine(shares...)
	require.NotNil(t, err)
}

func TestEd25519FeldmanCombineSingle(t *testing.T) {
	scheme, err := feldman.NewDealer(2, 3, testCurve)
	require.NoError(t, err)
	require.NotNil(t, scheme)

	secret, err := testCurve.Scalar().Hash([]byte("test"))
	require.NoError(t, err)
	commitments, shares, err := scheme.Split(secret, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, shares)
	for _, s := range shares {
		err = feldman.Verify(s, commitments)
		require.NoError(t, err)
	}
	secret2, err := scheme.Combine(shares...)
	require.NoError(t, err)
	require.Equal(t, secret2, secret)
}

func TestEd25519FeldmanAllCombinations(t *testing.T) {
	scheme, err := feldman.NewDealer(3, 5, testCurve)
	require.NoError(t, err)
	require.NotNil(t, scheme)

	secret, err := testCurve.Scalar().Hash([]byte("test"))
	require.NoError(t, err)
	commitments, shares, err := scheme.Split(secret, crand.Reader)
	for _, s := range shares {
		err = feldman.Verify(s, commitments)
		require.NoError(t, err)
	}
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
				require.Equal(t, rSecret, secret)
			}
		}
	}
}
