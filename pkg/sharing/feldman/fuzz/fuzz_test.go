package fuzz

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/pallas"
	"github.com/copperexchange/knox-primitives/pkg/sharing/feldman"
)

var allCurves = []curves.Curve{k256.New(), p256.New(), edwards25519.New(), pallas.New()}

func Fuzz_Test(f *testing.F) {
	f.Add(uint(0), []byte("secret"), int64(0))
	f.Fuzz(func(t *testing.T, curveIndex uint, secretBytes []byte, randomSeed int64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		prng := rand.New(rand.NewSource(randomSeed))

		scheme, err := feldman.NewDealer(3, 5, curve)
		require.NoError(t, err)
		secret := curve.Scalar().Hash(secretBytes)
		commitments, shares, err := scheme.Split(secret, prng)
		require.Nil(t, err)
		require.NotNil(t, shares)
		for _, s := range shares {
			err = feldman.Verify(s, commitments)
			require.Nil(t, err)
		}
		secret2, err := scheme.Combine(shares...)
		require.Nil(t, err)
		require.Equal(t, secret2, secret)
	})
}
