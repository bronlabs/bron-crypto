package bitstring_test

import (
	"os"
	"testing"

	"github.com/copperexchange/knox-primitives/internal"
	"github.com/copperexchange/knox-primitives/pkg/base/bitstring"
)

func Test_MeasureConstantTime_SelectBit(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	vector := internal.GetBigEndianBytesWithLowestBitsSet(512, 0)
	var tI int
	internal.RunMeasurement(500, "bitstring_selectbit", func(i int) {
		vector[i>>3] = 0x01 << (i & 0x07)
		tI = i
	}, func() {
		bitstring.SelectBit(vector, tI)
	})
}

func Test_MeasureConstantTime_TransposeBooleanMatrix(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	inputMatrix := [][]byte{}
	internal.RunMeasurement(500, "bitstring_Transpose", func(i int) {
		inputMatrix = [][]byte{
			internal.GetBigEndianBytesWithLowestBitsSet(512, i),
			internal.GetBigEndianBytesWithLowestBitsSet(512, i),
			internal.GetBigEndianBytesWithLowestBitsSet(512, i),
			internal.GetBigEndianBytesWithLowestBitsSet(512, i),
			internal.GetBigEndianBytesWithLowestBitsSet(512, i),
			internal.GetBigEndianBytesWithLowestBitsSet(512, i),
			internal.GetBigEndianBytesWithLowestBitsSet(512, i),
			internal.GetBigEndianBytesWithLowestBitsSet(512, i),
		}
	}, func() {
		bitstring.TransposePackedBits(inputMatrix)
	})
}
