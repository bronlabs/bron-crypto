package curveutils_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
)

var TestCurves = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
	edwards25519.NewCurve(),
	bls12381.NewG1(),
	bls12381.NewG2(),
	// curve25519.NewCurve(),
	pallas.NewCurve(),
}

func Test_ScalarMarshalRoundTrip(t *testing.T) {
	t.Parallel()
	for _, c := range TestCurves {
		curve := c
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			initial, err := curve.ScalarField().Random(crand.Reader)
			require.NoError(t, err)

			t.Run("json", func(t *testing.T) {
				t.Parallel()

				marshalled, err := initial.MarshalJSON()
				require.NoError(t, err)
				require.NotNil(t, marshalled)

				deserialized, err := curveutils.NewScalarFromJSON(marshalled)
				require.NoError(t, err)
				require.Equal(t, initial.ScalarField().Name(), deserialized.ScalarField().Name())
				require.EqualValues(t, initial.Bytes(), deserialized.Bytes())

				// below is to ensure the G field of the bls scalars are being set correctly.
				require.Equal(t, initial.ScalarField().Curve().Name(), deserialized.ScalarField().Curve().Name())
			})
			t.Run("binary", func(t *testing.T) {
				t.Parallel()

				marshalled, err := initial.MarshalBinary()
				require.NoError(t, err)
				require.NotNil(t, marshalled)

				deserialized, err := curveutils.NewScalarFromBinary(marshalled)
				require.NoError(t, err)
				require.Equal(t, initial.ScalarField().Name(), deserialized.ScalarField().Name())
				require.EqualValues(t, initial.Bytes(), deserialized.Bytes())

				// below is to ensure the G field of the bls scalars are being set correctly.
				require.Equal(t, initial.ScalarField().Curve().Name(), deserialized.ScalarField().Curve().Name())
			})
		})
	}
}

func Test_BaseFieldElementMarshalRoundTrip(t *testing.T) {
	t.Parallel()
	for _, c := range TestCurves {
		curve := c
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			initial, err := curve.BaseField().Random(crand.Reader)
			require.NoError(t, err)

			t.Run("json", func(t *testing.T) {
				t.Parallel()

				marshalled, err := initial.MarshalJSON()
				require.NoError(t, err)
				require.NotNil(t, marshalled)

				deserialized, err := curveutils.NewBaseFieldElementFromJSON(marshalled)
				require.NoError(t, err)
				require.Equal(t, initial.BaseField().Name(), deserialized.BaseField().Name())
				require.EqualValues(t, initial.Bytes(), deserialized.Bytes())
			})
			t.Run("binary", func(t *testing.T) {
				t.Parallel()

				marshalled, err := initial.MarshalBinary()
				require.NoError(t, err)
				require.NotNil(t, marshalled)

				deserialized, err := curveutils.NewBaseFieldElementFromBinary(marshalled)
				require.NoError(t, err)
				require.Equal(t, initial.BaseField().Name(), deserialized.BaseField().Name())
				require.EqualValues(t, initial.Bytes(), deserialized.Bytes())
			})
		})
	}
}

func Test_PointMarshalRoundTrip(t *testing.T) {
	t.Parallel()
	for _, c := range TestCurves {
		curve := c
		t.Run(curve.Name(), func(t *testing.T) {
			t.Parallel()
			initial, err := curve.Random(crand.Reader)
			require.NoError(t, err)

			t.Run("json", func(t *testing.T) {
				t.Parallel()

				marshalled, err := initial.MarshalJSON()
				require.NoError(t, err)
				require.NotNil(t, marshalled)

				deserialized, err := curveutils.NewPointFromJSON(marshalled)
				require.NoError(t, err)
				require.Equal(t, initial.Curve().Name(), deserialized.Curve().Name())
				require.EqualValues(t, initial.ToAffineUncompressed(), deserialized.ToAffineUncompressed())
			})
			t.Run("binary", func(t *testing.T) {
				t.Parallel()

				marshalled, err := initial.MarshalBinary()
				require.NoError(t, err)
				require.NotNil(t, marshalled)

				deserialized, err := curveutils.NewPointFromBinary(marshalled)
				require.NoError(t, err)
				require.Equal(t, initial.Curve().Name(), deserialized.Curve().Name())
				require.EqualValues(t, initial.ToAffineUncompressed(), deserialized.ToAffineUncompressed())
			})
		})
	}
}
