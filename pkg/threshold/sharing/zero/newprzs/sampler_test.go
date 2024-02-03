package newprzs_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"gonum.org/v1/gonum/stat/combin"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/newprzs"
)

func Test_Sampler(t *testing.T) {
	threshold := 3
	n := 8
	curve := k256.NewCurve()

	keys, err := newprzs.Deal(n, threshold-1, curve.ScalarField(), crand.Reader)
	require.NoError(t, err)

	samplers := make([]*newprzs.Sampler, n)
	for i, key := range keys {
		samplers[i] = newprzs.NewSampler(i, n, threshold-1, key)
	}

	samples := make([]curves.Scalar, n)
	for i, sampler := range samplers {
		samples[i] = sampler.SampleZero()
		require.False(t, samples[i].IsZero())
	}

	combinations := combin.Combinations(n, threshold+1)
	secrets := make([]curves.Scalar, 0)
	for _, combination := range combinations {
		shares := make([]*shamir.Share, len(combination))
		for i, c := range combination {
			shares[i] = &shamir.Share{
				Id:    c + 1,
				Value: samples[c],
			}
		}
		dealer, err := shamir.NewDealer(threshold+1, n, curve)
		require.NoError(t, err)
		secret, err := dealer.Combine(shares...)
		require.NoError(t, err)
		secrets = append(secrets, secret)
	}

	for i := 0; i < len(secrets)-1; i++ {
		require.Zero(t, secrets[i].Cmp(secrets[i+1]))
	}
}
