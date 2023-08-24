package bitstring_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
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

func Test_MeasureConstantTime_XorBytes(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	in := [][]byte{
		internal.GetBigEndianBytesWithLowestBitsSet(512, 512),
		internal.GetBigEndianBytesWithLowestBitsSet(512, 512),
		internal.GetBigEndianBytesWithLowestBitsSet(512, 512),
	}
	out := []byte{}
	internal.RunMeasurement(500, "bitstring_XorBytes", func(i int) {
		out = internal.GetBigEndianBytesWithLowestBitsSet(512, i)
	}, func() {
		bitstring.XorBytesInPlace(out, in...)
	})
}

func Test_MeasureConstantTime_XorBytesNew(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	in := [][]byte{
		{0x00, 0x04, 0x8, 0x00},
		{0x01, 0x01, 0x01, 0x01},
		{0x02, 0x02, 0x02, 0x01},
	}
	out, err := bitstring.XorBytes(in...)
	require.NoError(t, err)
	require.Equal(t, []byte{0x03, 0x07, 0x0B, 0x00}, out)
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
