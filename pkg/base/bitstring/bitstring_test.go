package bitstring_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
)

func TestSelectBit(t *testing.T) {
	t.Parallel()

	inputVector := []byte{
		0b00010010, 0b00110100,
		0b01010110, 0b01111000,
		0b10011010, 0b10111100,
		0b11011110, 0b11110000,
	}
	expectedVector := []byte{
		0, 1, 0, 0, 1, 0, 0, 0, // 0b00010010
		0, 0, 1, 0, 1, 1, 0, 0, // 0b00110100
		0, 1, 1, 0, 1, 0, 1, 0, // 0b01010110
		0, 0, 0, 1, 1, 1, 1, 0, // 0b01111000
		0, 1, 0, 1, 1, 0, 0, 1, // 0b10011010
		0, 0, 1, 1, 1, 1, 0, 1, // 0b10111100
		0, 1, 1, 1, 1, 0, 1, 1, // 0b11011110
		0, 0, 0, 0, 1, 1, 1, 1, // 0b11110000
	}
	for i := 0; i < len(inputVector)*8; i++ {
		output := bitstring.SelectBit(inputVector, i)
		require.Equalf(t, expectedVector[i], output, "i=%d", i)
	}

}

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
			output1 := bitstring.SelectBit(inputMatrix[i], j)
			output2 := bitstring.SelectBit(transposedMatrix[j][:], i)

			require.Equal(t,
				output1,
				output2)
		}
	}
}

func TestRepeatBits(t *testing.T) {
	t.Parallel()

	inputVector := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}
	for nRepetitions := 1; nRepetitions < 8; nRepetitions++ {
		outputVector := bitstring.RepeatBits(inputVector, nRepetitions)
		for i := 0; i < len(inputVector)*8; i++ {
			for j := 0; j < nRepetitions; j++ {
				output := bitstring.SelectBit(outputVector, i*nRepetitions+j)
				input := bitstring.SelectBit(inputVector, i)
				require.Equalf(t, input, output, "i=%d, j=%d", i, j)
			}
		}
	}
}

func TestUnpackBits(t *testing.T) {
	t.Parallel()

	inputVector := []byte{
		0b01001000, 0b00101100,
		0b01101010, 0b00011110,
		0b01011001, 0b00111101,
		0b01111011, 0b00001111,
	}
	outputVector := bitstring.UnpackBits(inputVector)
	for i := 0; i < len(inputVector)*8; i++ {
		input := bitstring.SelectBit(inputVector, i)
		require.Equal(t, input, outputVector[i])
	}
}

func TestPackBits(t *testing.T) {
	t.Parallel()

	inputVector := []byte{0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0}
	outputVector := bitstring.PackBits(inputVector)
	for i := 0; i < len(inputVector); i++ {
		output := bitstring.SelectBit(outputVector, i)
		require.Equal(t, inputVector[i], output)
	}
}
