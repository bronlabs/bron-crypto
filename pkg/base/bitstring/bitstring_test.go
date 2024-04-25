package bitstring_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
)

func TestReverseBytes1(t *testing.T) {

	t.Run("ReverseBytes is an involution", func(t *testing.T) {
		t.Parallel()

		inputArray := [][]byte{
			{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			{0x21, 0x43, 0x65, 0x87, 0xA9},
			{0x31, 0x53},
		}

		for index, input := range inputArray {
			t.Run(fmt.Sprintf("iteration %d", index), func(t *testing.T) {
				t.Parallel()

				result := bitstring.ReverseBytes(bitstring.ReverseBytes(input))

				require.Equal(t, result, input)
			})
		}
	})

	t.Run("Reverse of an empty array is itself", func(t *testing.T) {
		t.Parallel()
		input := []byte{}
		result := bitstring.ReverseBytes(input)

		require.Equal(t, result, input)
	})
}

func TestPadToLeft(t *testing.T) {
	t.Parallel()

	inputArray := [][]byte{
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

	for _, input := range inputArray {
		for _, padLength := range inputPadLengths {
			if padLength <= 0 {
				t.Run(fmt.Sprintf("nothing will be padded if padLength <=0 input: %v padLength: %v", input, padLength), func(t *testing.T) {
					t.Parallel()

					result := bitstring.PadToLeft(input, padLength)

					require.Equal(t, result, input)
				})
			} else {
				t.Run(fmt.Sprintf("input will be padded to the with padLength number of zeros input: %v padLength: %v", input, padLength), func(t *testing.T) {
					t.Parallel()

					result := bitstring.PadToLeft(input, padLength)

					require.Len(t, result, padLength+len(input))

					for i := 0; i < padLength; i++ {
						require.Equal(t, byte(0x00), result[i])
					}
					require.Equal(t, input, result[padLength:])
				})
			}
		}
	}
}

func TestPadToRight(t *testing.T) {
	t.Parallel()

	inputArray := [][]byte{
		{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
		{0x21},
		{},
	}

	inputPadLengths := []int{
		0,
		-1,
		4,
		1,
		4,
		1,
	}

	for _, input := range inputArray {
		for _, padLength := range inputPadLengths {
			if padLength <= 0 {
				t.Run(fmt.Sprintf("nothing will be padded if padLength <=0 input: %v padLength: %v", input, padLength), func(t *testing.T) {
					t.Parallel()

					result := bitstring.PadToRight(input, padLength)

					require.Equal(t, result, input)

				})
			} else {
				t.Run(fmt.Sprintf("input will be padded to the with padLength number of zeros input: %v padLength: %v", input, padLength), func(t *testing.T) {

					t.Parallel()

					result := bitstring.PadToRight(input, padLength)

					require.Len(t, result, padLength+len(input))

					require.Equal(t, input, result[:len(input)])
					for i := len(input); i < len(result); i++ {
						require.Equal(t, byte(0x00), result[i])
					}
				})
			}
		}
	}
}

func TestTransposePackedBits(t *testing.T) {
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
			output1 := bitstring.PackedBits(inputMatrix[i]).Get(uint(j))
			output2 := bitstring.PackedBits(transposedMatrix[j]).Get(uint(i))

			require.Equal(t,
				output1,
				output2)
		}
	}

	t.Run("Transpose of identity matrix is identity matrix", func(t *testing.T) {
		t.Parallel()

		inputMatrix := [][]uint8{
			bitstring.PackedBits([]uint8{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
			bitstring.PackedBits([]uint8{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
			bitstring.PackedBits([]uint8{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}),
			bitstring.PackedBits([]uint8{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}),
			bitstring.PackedBits([]uint8{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}),
			bitstring.PackedBits([]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}),
			bitstring.PackedBits([]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}),
			bitstring.PackedBits([]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
		}
		result, _ := bitstring.TransposePackedBits(inputMatrix)

		require.Equal(t, inputMatrix, result)
	})
	t.Run("Number of rows should be a multiple of 8", func(t *testing.T) {
		t.Parallel()

		inputMatrix := [][]byte{
			bitstring.PackedBits([]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}),
			bitstring.PackedBits([]byte{0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB}),
			bitstring.PackedBits([]byte{0x31, 0x53, 0x75, 0x97, 0xB9, 0xDB}),
			bitstring.PackedBits([]byte{0x41, 0x63, 0x85, 0xA7, 0xC9, 0xEB}),
			bitstring.PackedBits([]byte{0x51, 0x73, 0x95, 0xB7, 0xD9, 0xFB}),
			bitstring.PackedBits([]byte{0x61, 0x83, 0xA5, 0xC7, 0xE9, 0x0B}),
			bitstring.PackedBits([]byte{0x71, 0x93, 0xB5, 0xD7, 0xF9, 0x1B}),
			bitstring.PackedBits([]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}),
			bitstring.PackedBits([]byte{0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB}),
			bitstring.PackedBits([]byte{0x31, 0x53, 0x75, 0x97, 0xB9, 0xDB}),
			bitstring.PackedBits([]byte{0x41, 0x63, 0x85, 0xA7, 0xC9, 0xEB}),
			bitstring.PackedBits([]byte{0x51, 0x73, 0x95, 0xB7, 0xD9, 0xFB}),
			bitstring.PackedBits([]byte{0x61, 0x83, 0xA5, 0xC7, 0xE9, 0x0B}),
			bitstring.PackedBits([]byte{0x71, 0x93, 0xB5, 0xD7, 0xF9, 0x1B}),
		}
		_, err := bitstring.TransposePackedBits(inputMatrix)
		require.Error(t, err)
	})
	t.Run("Input must be a 2D matrix", func(t *testing.T) {
		t.Parallel()

		inputMatrix := [][]byte{
			bitstring.PackedBits([]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}),
		}
		_, err := bitstring.TransposePackedBits(inputMatrix)
		require.Error(t, err)
	})
}

func TestToBytes32LEt(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		inputArray     int32
		expectedOutput []byte
	}{
		{
			name:           "Positive Integer",
			inputArray:     123456789,
			expectedOutput: []byte{0x15, 0xCD, 0x5B, 0x07},
		},
		// {
		// 	name:           "Negative Integer",
		// 	inputArray:     -123456789,
		// 	expectedOutput: []byte{0xEB, 0x32, 0xA4, 0xF8},
		// },
		{
			name:           "Zero",
			inputArray:     0,
			expectedOutput: []byte{0x00, 0x00, 0x00, 0x00},
		},
	}

	for index, tc := range testCases {
		t.Run(fmt.Sprintf("testName: %s input: %v index: %d", tc.name, tc.inputArray, index), func(t *testing.T) {
			t.Parallel()

			result := bitstring.ToBytes32LE(tc.inputArray)
			require.Equal(t, tc.expectedOutput, result)
		})
	}

	// t.Run("Convertig to bytes and reverting back to int should give us the same input", func(t *testing.T) {

	// 	input := -123456789
	// 	result := bitstring.ToBytesLE(input)
	// 	backToInt := binary.LittleEndian.Uint32(result)
	// 	// res := len(int(backToInt))
	// 	fmt.Println(input, backToInt)
	// 	require.Equal(t, input, int(backToInt))
	// })
}
func TestTruncateWithEllipsis(t *testing.T) {
	t.Parallel()

	inputText := []struct {
		name   string
		input  string
		output string
	}{
		{
			name:   "Output is the same as input since length of input doesn't exceed max length",
			input:  "Hello",
			output: "Hello",
		}, {
			name:   "Output is the same as input since length of input doesn't exceed max length",
			input:  "HelloWorld",
			output: "HelloWorld",
		}, {
			name:   "Output gets shortened when length of input exceeds max length",
			input:  "Hello, World!",
			output: "Hello, Wor...(3)",
		},
	}

	maxLength := 10

	for index, tc := range inputText {
		t.Run(fmt.Sprintf("testname: %s input: %s index: %d", tc.name, tc.input, index), func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.output, bitstring.TruncateWithEllipsis(tc.input, maxLength))
		})
	}
}

func TestMemclr(t *testing.T) {
	t.Parallel()

	testCase := []struct {
		name   string
		input  []int
		output []int
	}{
		{
			name:   "a non-empty array is to going to have the same length but all the elements would be replaced with 0",
			input:  []int{1, 2, 3, 4},
			output: []int{0, 0, 0, 0},
		}, {
			name:   "a non-empty array is to going to have the same length but all the elements would be replaced with 0",
			input:  []int{10, 20, 30, 40},
			output: []int{0, 0, 0, 0},
		}, {
			name:   "a non-empty array is to going to have the same length but all the elements would be replaced with 0",
			input:  []int{100, 200, 300, 400},
			output: []int{0, 0, 0, 0},
		}, {
			name:   "a non-empty array is to going to have the same length but all the elements would be replaced with 0",
			input:  []int{1000000000, 2000000000, 3000000000, 4000000000},
			output: []int{0, 0, 0, 0},
		}, {
			name:   "Empty array is going to stay empty after memclr",
			input:  []int{},
			output: []int{},
		},
	}

	for index, tc := range testCase {
		t.Run(fmt.Sprintf("testname: %s index: %d", tc.name, index), func(t *testing.T) {
			t.Parallel()

			bitstring.Memclr(tc.input)
			require.Equal(t, tc.output, tc.input)
		})
	}
}
