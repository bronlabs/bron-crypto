package curves_test

import (
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"
)

func Test_FieldElementSetNatToOne_BigEndian(t *testing.T) {
	for _, curve := range TestCurves {
		boundedCurve := curve
		t.Run(boundedCurve.Name(), func(t *testing.T) {
			oneBigEndian := make([]byte, boundedCurve.BaseField().FieldBytes())

			if boundedCurve.BaseField().ExtensionDegree().Uint64() == 1 {
				oneBigEndian[len(oneBigEndian)-1] = 0x1
			} else {
				oneBigEndian[len(oneBigEndian)/2-1] = 0x1
			}
			oneNat := new(saferith.Nat).SetUint64(1)
			// Check cast from-to Nat
			realFeOne := boundedCurve.BaseField().One()
			feOne := boundedCurve.BaseField().Element().SetNat(oneNat)
			require.EqualValues(t, realFeOne.Bytes(), feOne.Bytes())
			require.EqualValues(t, oneBigEndian, feOne.Bytes())
			// Check if the internal value is treated as a one
			oneTimesOne := feOne.Mul(feOne)
			require.True(t, feOne.IsOne())
			require.True(t, !feOne.IsZero())
			require.True(t, oneTimesOne.IsOne() && !oneTimesOne.IsZero())
		})
	}
}

func Test_FieldElementSetBytesToOne_BigEndian(t *testing.T) {
	for _, curve := range TestCurves {
		boundedCurve := curve
		t.Run(boundedCurve.Name(), func(t *testing.T) {
			oneBigEndian := make([]byte, boundedCurve.BaseField().FieldBytes())

			if boundedCurve.BaseField().ExtensionDegree().Uint64() == 1 {
				oneBigEndian[len(oneBigEndian)-1] = 0x1
			} else {
				oneBigEndian[len(oneBigEndian)/2-1] = 0x1
			}
			// Check cast from-to bytes
			feOne, err := boundedCurve.BaseField().Element().SetBytes(oneBigEndian)
			require.NoError(t, err)
			require.EqualValues(t, oneBigEndian, feOne.Bytes())
			// Check if the internal value is treated as a one
			oneTimesOne := feOne.Mul(feOne)
			require.True(t, feOne.IsOne() && !feOne.IsZero())
			require.True(t, oneTimesOne.IsOne() && !oneTimesOne.IsZero())
		})
	}
}

func Test_FieldElementSetBytesWideToOne_BigEndian(t *testing.T) {
	for _, curve := range TestCurves {
		boundedCurve := curve
		t.Run(boundedCurve.Name(), func(t *testing.T) {
			oneBigEndian := make([]byte, boundedCurve.BaseField().WideFieldBytes())
			extensionDegree := boundedCurve.BaseField().ExtensionDegree().Uint64()
			if extensionDegree == 1 {
				oneBigEndian[len(oneBigEndian)-1] = 0x1
			} else {
				oneBigEndian[len(oneBigEndian)/2-1] = 0x1
			}
			// Check cast from-to Nat
			feOne, err := boundedCurve.BaseField().Element().SetBytesWide(oneBigEndian)
			require.NoError(t, err)
			feOneLength := len(feOne.Bytes())

			if extensionDegree == 1 {
				require.EqualValues(t, oneBigEndian[len(oneBigEndian)-feOneLength:], feOne.Bytes())
			} else {
				l := len(oneBigEndian)
				actualA := feOne.Bytes()[:feOneLength/2]
				expectedA := oneBigEndian[l/4 : l/2]
				require.EqualValues(t, expectedA, actualA)
				require.Contains(t, actualA, byte(0x01))

				actualB := feOne.Bytes()[feOneLength/2:]
				expectedB := oneBigEndian[3*l/4:]
				require.EqualValues(t, expectedB, actualB)
				require.NotContains(t, actualB, byte(0x01))
			}

			// Check if the internal value is treated as a one
			oneTimesOne := feOne.Mul(feOne)
			require.True(t, feOne.IsOne() && !feOne.IsZero())
			require.True(t, oneTimesOne.IsOne() && !oneTimesOne.IsZero())
		})
	}
}
