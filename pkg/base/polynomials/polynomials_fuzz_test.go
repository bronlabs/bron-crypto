package polynomials_test

import (
	"math/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/p256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/pallas"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/polynomials"
	"github.com/bronlabs/krypton-primitives/pkg/base/polynomials/interpolation/lagrange"
)

var allCurves = []curves.Curve{k256.NewCurve(), p256.NewCurve(), edwards25519.NewCurve(), pallas.NewCurve()}

func FuzzPolynomial(f *testing.F) {
	f.Add(uint(0), []byte("test"), int64(0), uint(4), uint64(1))
	f.Fuzz(func(t *testing.T, curveIndex uint, s []byte, randomSeed int64, degree uint, x uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		secret, err := curve.ScalarField().Hash(s)
		require.NoError(t, err)
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
		poly.Evaluate(curve.ScalarField().New(x))
	})
}

func FuzzInterpolate(f *testing.F) {
	f.Add(uint(0), uint64(1), uint64(2), uint64(1))
	f.Fuzz(func(t *testing.T, curveIndex uint, x uint64, y uint64, at uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		_, err := lagrange.Interpolate(curve, []curves.Scalar{curve.ScalarField().New(x)}, []curves.Scalar{curve.ScalarField().New(y)}, curve.ScalarField().New(at))
		require.NoError(t, err)
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
		_, err = lagrange.InterpolateInTheExponent(curve, []curves.Scalar{curve.ScalarField().New(x)}, []curves.Point{p}, curve.ScalarField().New(at))
		require.NoError(t, err)
	})
}
