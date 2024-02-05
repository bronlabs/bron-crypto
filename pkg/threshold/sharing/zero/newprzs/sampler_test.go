package newprzs_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"gonum.org/v1/gonum/stat/combin"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/chacha20"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/newprzs"
)

func Test_Sampler(t *testing.T) {
	t.Parallel()

	threshold := 4
	n := 8
	przsT := threshold - 2
	prssT := threshold - 1
	curve := k256.NewCurve()
	sessionId := []byte("testSessionId")
	csprngFactory, err := chacha20.NewChachaPRNG(nil, nil)
	require.NoError(t, err)

	t.Run("should shamir share zero", func(t *testing.T) {
		t.Parallel()
		keys, err := newprzs.Deal(n, przsT, crand.Reader)
		require.NoError(t, err)

		samplers := make([]*newprzs.Sampler, n)
		for i, key := range keys {
			samplers[i], err = newprzs.NewSampler(i, n, przsT, curve.ScalarField(), sessionId, key, csprngFactory)
			require.NoError(t, err)
		}

		samples := make([]curves.Scalar, n)
		for i, sampler := range samplers {
			samples[i], err = sampler.SampleZero()
			require.NoError(t, err)
			require.False(t, samples[i].IsZero())
		}

		combinations := combin.Combinations(n, threshold)
		secrets := make([]curves.Scalar, 0)
		for _, combination := range combinations {
			shares := make([]*shamir.Share, len(combination))
			for i, c := range combination {
				shares[i] = &shamir.Share{
					Id:    c + 1,
					Value: samples[c],
				}
			}
			dealer, err := shamir.NewDealer(threshold, n, curve)
			require.NoError(t, err)
			secret, err := dealer.Combine(shares...)
			require.NoError(t, err)
			secrets = append(secrets, secret)
		}

		for _, secret := range secrets {
			require.True(t, secret.IsZero())
		}
	})

	t.Run("should shamir share random", func(t *testing.T) {
		keys, err := newprzs.Deal(n, prssT, crand.Reader)
		require.NoError(t, err)

		samplers := make([]*newprzs.Sampler, n)
		for i, key := range keys {
			samplers[i], err = newprzs.NewSampler(i, n, prssT, curve.ScalarField(), sessionId, key, csprngFactory)
			require.NoError(t, err)
		}

		samples := make([]curves.Scalar, n)
		for i, sampler := range samplers {
			samples[i], err = sampler.SampleRandom()
			require.NoError(t, err)
			require.False(t, samples[i].IsZero())
		}

		combinations := combin.Combinations(n, threshold)
		secrets := make([]curves.Scalar, 0)
		for _, combination := range combinations {
			shares := make([]*shamir.Share, len(combination))
			for i, c := range combination {
				shares[i] = &shamir.Share{
					Id:    c + 1,
					Value: samples[c],
				}
			}
			dealer, err := shamir.NewDealer(threshold, n, curve)
			require.NoError(t, err)
			secret, err := dealer.Combine(shares...)
			require.NoError(t, err)
			secrets = append(secrets, secret)
		}

		for i := 0; i < len(secrets)-1; i++ {
			require.True(t, secrets[i].Equal(secrets[i+1]))
		}
	})
}
