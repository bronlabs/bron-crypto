package fuzz

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

var allCurves = []curves.Curve{k256.New(), p256.New(), edwards25519.New(), pallas.New()}

func Fuzz_Test(f *testing.F) {
	f.Add(uint(0), []byte("msg"), int64(0))
	f.Fuzz(func(t *testing.T, curveIndex uint, message []byte, randomSeed int64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		prng := rand.New(rand.NewSource(randomSeed))

		scheme, err := shamir.NewDealer(2, 3, curve)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}

		shares, err := scheme.Split(curve.Scalar().Hash(message), prng)
		require.Nil(t, err)
		require.NotNil(t, shares)
		secret, err := scheme.Combine(shares...)
		require.Nil(t, err)
		require.Equal(t, secret, curve.Scalar().Hash(message))
	})
}
