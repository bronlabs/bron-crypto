package edwards25519_tester_test

import (
	crand "crypto/rand"
	filippo "filippo.io/edwards25519"
	edwards25519Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519/impl"
	pointsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/points"
	edwards25519Tester "github.com/bronlabs/bron-crypto/tools/edwards25519-tester"
	"testing"
)

func Test_PointAdd(t *testing.T) {
	t.Parallel()

	for range 1 << 20 {
		filippoPointA, primitivesPointA := edwards25519Tester.GenerateRandomPoints(t, crand.Reader)
		edwards25519Tester.RequirePointsEqual(t, filippoPointA, primitivesPointA)

		filippoPointB, primitivesPointB := edwards25519Tester.GenerateRandomPoints(t, crand.Reader)
		edwards25519Tester.RequirePointsEqual(t, filippoPointB, primitivesPointB)

		filippoPointC := new(filippo.Point).Add(filippoPointA, filippoPointB)
		primitivesPointC := new(edwards25519Impl.Point)
		primitivesPointC.Add(primitivesPointA, primitivesPointB)
		edwards25519Tester.RequirePointsEqual(t, filippoPointC, primitivesPointC)
	}
}

func Test_PointSub(t *testing.T) {
	t.Parallel()

	for range 1 << 20 {
		filippoPointA, primitivesPointA := edwards25519Tester.GenerateRandomPoints(t, crand.Reader)
		edwards25519Tester.RequirePointsEqual(t, filippoPointA, primitivesPointA)

		filippoPointB, primitivesPointB := edwards25519Tester.GenerateRandomPoints(t, crand.Reader)
		edwards25519Tester.RequirePointsEqual(t, filippoPointB, primitivesPointB)

		filippoPointC := new(filippo.Point).Subtract(filippoPointA, filippoPointB)
		primitivesPointC := new(edwards25519Impl.Point)
		primitivesPointC.Sub(primitivesPointA, primitivesPointB)
		edwards25519Tester.RequirePointsEqual(t, filippoPointC, primitivesPointC)
	}
}

func Test_PointNeg(t *testing.T) {
	t.Parallel()

	for range 1 << 21 {
		filippoPointA, primitivesPointA := edwards25519Tester.GenerateRandomPoints(t, crand.Reader)
		edwards25519Tester.RequirePointsEqual(t, filippoPointA, primitivesPointA)

		filippoPointC := new(filippo.Point).Negate(filippoPointA)
		primitivesPointC := new(edwards25519Impl.Point)
		primitivesPointC.Neg(primitivesPointA)
		edwards25519Tester.RequirePointsEqual(t, filippoPointC, primitivesPointC)
	}
}

func Test_PointDouble(t *testing.T) {
	t.Parallel()

	for range 1 << 21 {
		filippoPointA, primitivesPointA := edwards25519Tester.GenerateRandomPoints(t, crand.Reader)
		edwards25519Tester.RequirePointsEqual(t, filippoPointA, primitivesPointA)

		filippoPointC := new(filippo.Point).Add(filippoPointA, filippoPointA)
		primitivesPointC := new(edwards25519Impl.Point)
		primitivesPointC.Double(primitivesPointA)
		edwards25519Tester.RequirePointsEqual(t, filippoPointC, primitivesPointC)
	}
}

func Test_PointClearCofactor(t *testing.T) {
	t.Parallel()

	for range 1 << 21 {
		filippoPointA, primitivesPointA := edwards25519Tester.GenerateRandomPoints(t, crand.Reader)
		edwards25519Tester.RequirePointsEqual(t, filippoPointA, primitivesPointA)

		filippoPointC := new(filippo.Point).MultByCofactor(filippoPointA)
		primitivesPointC := new(edwards25519Impl.Point)
		primitivesPointC.ClearCofactor(primitivesPointA)
		edwards25519Tester.RequirePointsEqual(t, filippoPointC, primitivesPointC)
	}
}

func Test_PointScalarBaseMul(t *testing.T) {
	t.Parallel()

	for range 1 << 20 {
		filippoScalar, primitivesScalar := edwards25519Tester.GenerateRandomScalars(t, crand.Reader)
		edwards25519Tester.RequireScalarsEqual(t, filippoScalar, primitivesScalar)

		filippoPointC := new(filippo.Point).ScalarBaseMult(filippoScalar)
		primitiveGenerator := new(edwards25519Impl.Point)
		primitiveGenerator.SetGenerator()
		primitivePointC := new(edwards25519Impl.Point)
		pointsImpl.ScalarMul[*edwards25519Impl.Fp](primitivePointC, primitiveGenerator, primitivesScalar.Bytes())
		edwards25519Tester.RequirePointsEqual(t, filippoPointC, primitivePointC)
	}
}

func Test_PointScalarMul(t *testing.T) {
	t.Parallel()

	for range 1 << 18 {
		filippoScalar, primitivesScalar := edwards25519Tester.GenerateRandomScalars(t, crand.Reader)
		edwards25519Tester.RequireScalarsEqual(t, filippoScalar, primitivesScalar)

		filippoPointA, primitivesPointA := edwards25519Tester.GenerateRandomPoints(t, crand.Reader)
		edwards25519Tester.RequirePointsEqual(t, filippoPointA, primitivesPointA)

		filippoPointC := new(filippo.Point).ScalarMult(filippoScalar, filippoPointA)
		primitivePointC := new(edwards25519Impl.Point)
		pointsImpl.ScalarMul[*edwards25519Impl.Fp](primitivePointC, primitivesPointA, primitivesScalar.Bytes())
		edwards25519Tester.RequirePointsEqual(t, filippoPointC, primitivePointC)
	}
}
