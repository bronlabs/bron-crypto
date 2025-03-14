package shamir_test

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pallas"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

var allCurves = []curves.Curve{k256.NewCurve(), p256.NewCurve(), edwards25519.NewCurve(), pallas.NewCurve()}

func FuzzShamir(f *testing.F) {
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

		messageScalar, err := curve.ScalarField().Hash(message)
		require.NoError(t, err)
		shares, err := scheme.Split(messageScalar, prng)
		require.NoError(t, err)
		require.NotNil(t, shares)
		secret, err := scheme.Combine(shares...)
		require.NoError(t, err)
		require.Equal(t, secret, messageScalar)
	})
}

func FuzzLagrangeCoefficients(f *testing.F) {
	f.Add(uint(0), uint(1), uint(2), uint(3))
	f.Fuzz(func(t *testing.T, curveIndex uint, x1 uint, x2 uint, x3 uint) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		fmt.Println(curve.Name())
		_, err := shamir.LagrangeCoefficients(curve, []uint{x1, x2, x3})
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
	})
}
