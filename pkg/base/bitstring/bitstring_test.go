package bitstring_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
)

func TestReverseBytes(t *testing.T) {
	t.Parallel()

	inputMatrix := [][]byte{
		{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
		{0x21, 0x43, 0x65, 0x87, 0xA9},
		{0x31, 0x53},
	}
	for _, input := range inputMatrix {
		t.Run(fmt.Sprintf("%v", input), func(t *testing.T) {
			t.Parallel()

			//reverse of revese should be the same os original
			result := bitstring.ReverseBytes(input)
			result = bitstring.ReverseBytes(result)

			require.Equal(t, result, input)
		})
	}
	t.Run("empty array", func(t *testing.T) {
		t.Parallel()
		input := []byte{}
		result := bitstring.ReverseBytes(input)

		require.Equal(t, result, input)
	})
}

func TestPadToLeft(t *testing.T) {
	t.Parallel()

	inputMatrix := [][]byte{
		{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
		{0x21},
		{},
	}

	inputPadLengths := []int{
		0,
		1,
		4,
		-1,
	}

	for _, input := range inputMatrix {
		for _, padLength := range inputPadLengths {
			t.Run(fmt.Sprintf("%v, %v", input, padLength), func(t *testing.T) {
				t.Parallel()
	
				result := bitstring.PadToLeft(input, padLength)
	
				var expected []byte
				if padLength > 0 {
					expected = append(make([]byte, padLength), input...)
				} else {
					expected = input
				}
				require.Equal(t, expected, result)
			})
		}

	}
}

func TestPadToRight(t *testing.T) {
	t.Parallel()

	inputMatrix := [][]byte{
		{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
		{0x21},
		{},
	}

	inputPadLengths := []int{
		0,
		1,
		4,
		-1,
	}

	for _, input := range inputMatrix {
		for _, padLength := range inputPadLengths {
			t.Run(fmt.Sprintf("%v ,%v", input, padLength), func(t *testing.T) {
				t.Parallel()
	
				result := bitstring.PadToRight(input, padLength)
	
				var expected []byte
				if padLength > 0 {
					expected = make([]byte, len(input)+padLength)
					copy(expected, input)
	
				} else {
					expected = input
				}
				require.Equal(t, expected, result)
			})
		}
	}
}

func TestByteSubLE(t *testing.T) {
	t.Parallel()

	inputMatrix := [][]byte{
		{0x05, 0x01, 0x00, 0x00},
		{0x00, 0x00, 0x01, 0x00},
		{0x00, 0x00, 0x00, 0x01},
		{0x00, 0x00, 0x00, 0x00},
	}

	expectedOutput := [][]byte{
		{0x04, 0x01, 0x00, 0x00},
		{0xFF, 0xFF, 0x00, 0x00},
		{0xFF, 0xFF, 0xFF, 0x00},
		{0xFF, 0xFF, 0xFF, 0xFF}}

	for i, input := range inputMatrix {
		t.Run(fmt.Sprintf("Case %v", input), func(t *testing.T) {
			t.Parallel()

			bitstring.ByteSubLE(input)
			require.Equal(t, input, expectedOutput[i])
		})
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
			output1 := bitstring.PackedBits(inputMatrix[i]).Select(j)
			output2 := bitstring.PackedBits(transposedMatrix[j]).Select(i)

			require.Equal(t,
				output1,
				output2)
		}
	}

	t.Run("Test for input not having rows%8==0", func(t *testing.T) {
		t.Parallel()

		inputMatrix := [][]byte{
			{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			{0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB},
			{0x31, 0x53, 0x75, 0x97, 0xB9, 0xDB},
			{0x41, 0x63, 0x85, 0xA7, 0xC9, 0xEB},
			{0x51, 0x73, 0x95, 0xB7, 0xD9, 0xFB},
			{0x61, 0x83, 0xA5, 0xC7, 0xE9, 0x0B},
			{0x71, 0x93, 0xB5, 0xD7, 0xF9, 0x1B},
		}
		_, err := bitstring.TransposePackedBits(inputMatrix)
		require.Error(t, err)
	})
	t.Run("Testing 1D matrix", func(t *testing.T) {
		t.Parallel()

		inputMatrix := [][]byte{
			{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
		}
		_, err := bitstring.TransposePackedBits(inputMatrix)
		require.Error(t, err)
	})
}

func TestToBytesLE(t *testing.T) {
	t.Parallel()

	inputInt := []int{
		123456789,
		-123456789,
		0,
	}

	expectedOutput := [][]byte{
		{0x15, 0xCD, 0x5B, 0x07},
		{0xEB, 0x32, 0xA4, 0xF8},
		{0x00, 0x00, 0x00, 0x00},
	}

	for i, input := range inputInt {

		t.Run(fmt.Sprintf("Case %d", input), func(t *testing.T) {
			t.Parallel()

			require.Equal(t, expectedOutput[i], bitstring.ToBytesLE(input))
		})
	}
}

func TestTruncateWithEllipsis(t *testing.T) {
	t.Parallel()

	inputText := []string{
		"Hello",
		"HelloWorld",
		"Hello, World!",
		"",
	}

	expectedOutput := []string{
		"Hello",
		"HelloWorld",
		"Hello, Wor...(3)",
		"",
	}

	for i, input := range inputText {
		maxLength := 10
		t.Run(fmt.Sprintf("Case %s", input), func(t *testing.T) {
			t.Parallel()

			require.Equal(t, expectedOutput[i], bitstring.TruncateWithEllipsis(input, maxLength))
		})
	}
}

func TestMemclr(t *testing.T) {
	t.Parallel()

	inputMatrix := [][]int{
		{1, 2, 3, 4},
		{10, 20, 30, 40},
		{100, 200, 300, 4000},
		{1000000000, 2000000000, 300000000, 400000000},
		{},
	}
	expectedOutput := [][]int{
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, 0},
		{},
	}

	for i, input := range inputMatrix {
		t.Run(fmt.Sprintf("Case %v", input), func(t *testing.T) {
			t.Parallel()
			bitstring.Memclr(input)
			require.Equal(t, expectedOutput[i], input)
		})
	}
}
