package fuzz

import (
	"math/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton/pkg/base/curves/k256"
	"github.com/copperexchange/krypton/pkg/base/curves/p256"
	"github.com/copperexchange/krypton/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton/pkg/base/errs"
	"github.com/copperexchange/krypton/pkg/base/polynomials"
	"github.com/copperexchange/krypton/pkg/threshold/sharing/shamir"
)

var allCurves = []curves.Curve{k256.New(), p256.New(), edwards25519.New(), pallas.New()}

func Fuzz_Test_polynomial(f *testing.F) {
	f.Add(uint(0), []byte("test"), int64(0), 4, uint64(1))
	f.Fuzz(func(t *testing.T, curveIndex uint, s []byte, randomSeed int64, degree int, x uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		secret := curve.Scalar().Hash(s)
		prng := rand.New(rand.NewSource(randomSeed))

		poly, err := polynomials.NewRandomPolynomial(secret, degree, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}
		require.NotNil(t, poly)
		require.Equal(t, poly.Coefficients[0], secret)
		poly.Evaluate(curve.Scalar().New(x))
	})
}

func Fuzz_Test_LagrangeCoefficients(f *testing.F) {
	f.Add(uint(0), 1, 2, 3)
	f.Fuzz(func(t *testing.T, curveIndex uint, x1 int, x2 int, x3 int) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		_, err := shamir.LagrangeCoefficients(curve, []int{x1, x2, x3})
		require.NoError(t, err)
	})
}

func Fuzz_Test_Interpolate(f *testing.F) {
	f.Add(uint(0), uint64(1), uint64(2), uint64(1))
	f.Fuzz(func(t *testing.T, curveIndex uint, x uint64, y uint64, at uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		_, err := polynomials.Interpolate(curve, []curves.Scalar{curve.Scalar().New(x)}, []curves.Scalar{curve.Scalar().New(y)}, curve.Scalar().New(at))
		require.NoError(t, err)
	})
}

func Fuzz_Test_InterpolateInTheExponent(f *testing.F) {
	f.Add(uint(0), uint64(1), uint64(2), uint64(2), uint64(1))
	f.Fuzz(func(t *testing.T, curveIndex uint, x uint64, px uint64, py uint64, at uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		p, err := curve.Point().Set(
			new(saferith.Nat).SetUint64(px),
			new(saferith.Nat).SetUint64(py),
		)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}
		_, err = polynomials.InterpolateInTheExponent(curve, []curves.Scalar{curve.Scalar().New(x)}, []curves.Point{p}, curve.Scalar().New(at))
		require.NoError(t, err)
	})
}
