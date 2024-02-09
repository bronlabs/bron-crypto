package fuzz

import (
	"math/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/polynomials"
	polynomialsUtils "github.com/copperexchange/krypton-primitives/pkg/base/polynomials/utils"
)

var allCurves = []curves.Curve{k256.NewCurve(), p256.NewCurve(), edwards25519.NewCurve(), pallas.NewCurve()}

func FuzzPolynomial(f *testing.F) {
	f.Add(uint(0), []byte("test"), int64(0), 4, uint64(1))
	f.Fuzz(func(t *testing.T, curveIndex uint, s []byte, randomSeed int64, degree int, x uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		secret, err := curve.ScalarField().Hash(s)
		require.NoError(t, err)
		prng := rand.New(rand.NewSource(randomSeed))

		polySet := polynomials.GetScalarUnivariatePolynomialsSet(curve.ScalarField())
		poly, err := polySet.NewUnivariatePolynomialRandomWithIntercept(degree, secret, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}
		require.NotNil(t, poly)
		require.Equal(t, poly.Coefficients()[0], secret)
		poly.Eval(curve.ScalarField().New(x))
	})
}

func FuzzInterpolate(f *testing.F) {
	f.Add(uint(0), uint64(1), uint64(2), uint64(1))
	f.Fuzz(func(t *testing.T, curveIndex uint, x uint64, y uint64, at uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		polySet := polynomials.GetScalarUnivariatePolynomialsSet(curve.ScalarField())
		poly, err := polynomialsUtils.Interpolate(polySet, []curves.Scalar{curve.ScalarField().New(x)}, []curves.Scalar{curve.ScalarField().New(y)})
		require.NoError(t, err)
		poly.Eval(curve.ScalarField().New(at))
	})
}

func FuzzInterpolateInTheExponent(f *testing.F) {
	f.Add(uint(0), uint64(1), uint64(2), uint64(2), uint64(1))
	f.Fuzz(func(t *testing.T, curveIndex uint, x uint64, px uint64, py uint64, at uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		p, err := curve.NewPoint(
			curve.BaseField().Element().SetNat(new(saferith.Nat).SetUint64(px)),
			curve.BaseField().Element().SetNat(new(saferith.Nat).SetUint64(py)),
		)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}
		_, err = polynomialsUtils.InterpolateInTheExponent(curve, []curves.Scalar{curve.ScalarField().New(x)}, []curves.Point{p}, curve.ScalarField().New(at))
		require.NoError(t, err)
	})
}
