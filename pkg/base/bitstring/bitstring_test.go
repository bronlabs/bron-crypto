package bitstring_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
)

func TestTransposeBooleanMatrix(t *testing.T) {
	t.Parallel()

	// Test with a 8x6 matrix
	inputMatrix := [][]byte{
		{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
		{0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB},
		{0x31, 0x53, 0x75, 0x97, 0xB9, 0xDB},
		{0x41, 0x63, 0x85, 0xA7, 0xC9, 0xEB},
		{0x51, 0x73, 0x95, 0xB7, 0xD9, 0xFB},
		{0x61, 0x83, 0xA5, 0xC7, 0xE9, 0x0B},
		{0x71, 0x93, 0xB5, 0xD7, 0xF9, 0x1B},
		{0x81, 0xA3, 0xC5, 0xE7, 0x09, 0x2B},
	}
	transposedMatrix, err := bitstring.TransposePackedBits(inputMatrix)
	require.NoError(t, err)
	for i := 0; i < len(inputMatrix); i++ {
		for j := 0; j < len(transposedMatrix); j++ {
			// Check that the bit at position i in the jth row of the input matrix.
			// is equal to the bit at position j in the ith row of the transposed matrix.
			// using bitstring.SelectBit (careful! it takes a byte array as input)
			output1 := bitstring.PackedBits(inputMatrix[i]).Select(j)
			output2 := bitstring.PackedBits(transposedMatrix[j]).Select(i)

			require.Equal(t,
				output1,
				output2)
		}
	}
}
