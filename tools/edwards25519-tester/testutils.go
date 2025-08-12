package edwards25519_tester

import (
	"io"
	"testing"

	filippo "filippo.io/edwards25519"
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	edwards25519Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519/impl"
	"github.com/stretchr/testify/require"
)

func GenerateRandomPoints(tb testing.TB, prng io.Reader) (*filippo.Point, *edwards25519Impl.Point) {
	tb.Helper()

	for {
		pointSerialization := make([]byte, 32)
		_, err := io.ReadFull(prng, pointSerialization[:])
		require.NoError(tb, err)

		filippoPoint := new(filippo.Point)
		_, filippoErr := filippoPoint.SetBytes(pointSerialization[:])

		primitivesXSign := ct.Bool(pointSerialization[31] >> 7)
		primitivesYBytes := make([]byte, 32)
		copy(primitivesYBytes[:], pointSerialization[:])
		primitivesYBytes[31] &= 0x7f

		primitivesY := new(edwards25519Impl.Fp)
		ok := primitivesY.SetBytes(primitivesYBytes)
		require.True(tb, ok == 1)

		primitivesPoint := new(edwards25519Impl.Point)
		ok = primitivesPoint.SetFromAffineY(primitivesY)
		if filippoErr != nil {
			require.False(tb, ok == 1)
			continue
		} else {
			require.True(tb, ok == 1)
		}

		primitivesX := new(edwards25519Impl.Fp)
		ok = primitivesPoint.ToAffine(primitivesX, primitivesY)
		require.True(tb, ok == 1)
		if fieldsImpl.IsOdd(primitivesX) != primitivesXSign {
			primitivesPoint.Neg(primitivesPoint)
		}

		return filippoPoint, primitivesPoint
	}
}

func GenerateRandomScalars(tb testing.TB, prng io.Reader) (*filippo.Scalar, *edwards25519Impl.Fq) {
	tb.Helper()

	scalarSerialization := make([]byte, 64)
	_, err := io.ReadFull(prng, scalarSerialization[:])
	require.NoError(tb, err)

	filippoScalar, err := new(filippo.Scalar).SetUniformBytes(scalarSerialization[:])
	require.NoError(tb, err)

	primitivesScalar := new(edwards25519Impl.Fq)
	ok := primitivesScalar.SetBytesWide(scalarSerialization[:])
	require.True(tb, ok == 1)

	return filippoScalar, primitivesScalar
}

func RequirePointsEqual(tb testing.TB, filippoPoint *filippo.Point, primitivesPoint *edwards25519Impl.Point) {
	tb.Helper()

	filippoBytes := filippoPoint.Bytes()

	x := new(edwards25519Impl.Fp)
	y := new(edwards25519Impl.Fp)
	ok := primitivesPoint.ToAffine(x, y)
	require.True(tb, ok == 1)
	primitivesBytes := y.Bytes()
	primitivesBytes[31] |= byte(fieldsImpl.IsOdd(x) << 7)

	require.Equal(tb, filippoBytes, primitivesBytes)
}

func RequireScalarsEqual(tb testing.TB, filippoScalar *filippo.Scalar, primitivesScalar *edwards25519Impl.Fq) {
	tb.Helper()

	filippoScalarBytes := filippoScalar.Bytes()
	primitivesScalarBytes := primitivesScalar.Bytes()
	require.Equal(tb, filippoScalarBytes, primitivesScalarBytes)
}
