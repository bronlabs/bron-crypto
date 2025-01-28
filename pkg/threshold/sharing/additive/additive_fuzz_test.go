package additive_test

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/p256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/pasta"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/additive"
)

var allCurves = []curves.Curve{k256.NewCurve(), p256.NewCurve(), edwards25519.NewCurve(), pasta.NewPallasCurve()}

func Fuzz_Test(f *testing.F) {
	f.Add(uint(0), []byte("secret"), int64(0))
	f.Fuzz(func(t *testing.T, curveIndex uint, secretBytes []byte, randomSeed int64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		prng := rand.New(rand.NewSource(randomSeed))
		dealer, err := additive.NewDealer(5, curve)
		require.NoError(t, err)
		require.NotNil(t, dealer)

		secret, err := curve.ScalarField().Hash(secretBytes)
		require.NoError(t, err)

		shares, err := dealer.Split(secret, prng)
		require.NoError(t, err)
		require.NotNil(t, shares)
		require.Len(t, shares, 5)

		recomputedSecret, err := dealer.Combine(shares)
		require.NoError(t, err)
		require.NotNil(t, recomputedSecret)
		require.Zero(t, secret.Cmp(recomputedSecret))
	})
}
