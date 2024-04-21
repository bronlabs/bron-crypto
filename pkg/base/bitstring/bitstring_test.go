package bitstring_test

import (
	"encoding/binary"
	"fmt"

	"math/big"
	
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
)

func TestReverseBytes1(t *testing.T) {

	inputArray := [][]byte{
		{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
		{0x21, 0x43, 0x65, 0x87, 0xA9},
		{0x31, 0x53},
	}

	t.Run("ReverseBytes is an involution", func(t *testing.T) {
		t.Parallel()
		for index, input := range inputArray {
			t.Run(fmt.Sprintf("iteration %d", index), func(t *testing.T) {
				t.Parallel()

				result := bitstring.ReverseBytes(bitstring.ReverseBytes(input))

				require.Equal(t, result, input)
			})
		}
	})

	t.Run("Empty array", func(t *testing.T) {
		t.Parallel()
		input := []byte{}
		result := bitstring.ReverseBytes(input)

		require.Equal(t, result, input)
	})
}

func TestPadToLeft(t *testing.T) {
	t.Parallel()

	inputArray := [][]byte{
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

	t.Run("Testing PadToLeft", func(t *testing.T) {
		t.Parallel()

		for _, input := range inputArray {
			for _, padLength := range inputPadLengths {
				t.Run(fmt.Sprintf("input: %v, padLength: %v", input, padLength), func(t *testing.T) {
					t.Parallel()

					result := bitstring.PadToLeft(input, padLength)
					result := bitstring.PadToLeft(input, padLength)

					// checks if the length of the result==padLength+input
					// then checks if the first len(padlength) elemnts in the result are 0x00
					// checks if input[paslength:] is equal to result[paslength:]
					if padLength <= 0 {
						require.Equal(t, result, input)
					} else {
						require.Len(t, result, padLength+len(input))

						for i := 0; i < padLength; i++ {
							require.Equal(t, byte(0x00), result[i])
						}
						require.Equal(t, input, result[padLength:])
					}
				})
			}
		}
	})
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

	t.Run("Testing PadToLeft", func(t *testing.T) {
		t.Parallel()

		for _, input := range inputMatrix {
			for _, padLength := range inputPadLengths {
				t.Run(fmt.Sprintf("%v ,%v", input, padLength), func(t *testing.T) {
					t.Parallel()

					result := bitstring.PadToRight(input, padLength)
					result := bitstring.PadToRight(input, padLength)

					if padLength <= 0 {
						require.Equal(t, result, input)
					} else {
						require.Len(t, result, padLength+len(input))
						require.Equal(t, input, result[:len(input)])

						for i := len(input); i < len(result); i++ {
							require.Equal(t, byte(0x00), result[i])
						}
					}
				})
			}
		}
	})
}

func TestByteSubLE(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		inputArray     []byte
		expectedOutput []byte
	}{
		{
			inputArray:     []byte{0x05, 0x01, 0x00, 0x00},
			expectedOutput: []byte{0x04, 0x01, 0x00, 0x00},
		},
		{
			inputArray:     []byte{0x00, 0x00, 0x01, 0x00},
			expectedOutput: []byte{0xFF, 0xFF, 0x00, 0x00},
		},
		{
			inputArray:     []byte{0x00, 0x00, 0x00, 0x00},
			expectedOutput: []byte{0xFF, 0xFF, 0xFF, 0xFF},
		},
		{
			inputArray:     []byte{0x00, 0x00, 0x00, 0x01},
			expectedOutput: []byte{0xFF, 0xFF, 0xFF, 0x00},
		},
	}

	t.Run("Testing ByteSubLE", func(t *testing.T) {
		t.Parallel()
		for index, tc := range testCases {
			t.Run(fmt.Sprintf("iteration %d", index), func(t *testing.T) {
				t.Parallel()

				bitstring.ByteSubLE(tc.inputArray)
				require.Equal(t, tc.expectedOutput, tc.inputArray)
			})
		}
	})

	t.Run("Testing big.int", func(t *testing.T) {

		inputBigInt := new(big.Int).SetInt64(1 << 30) // there's an error for (1 << 40) 
		inputBytes := inputBigInt.Bytes() //returns a big-endian byte slice

		//convert BE to LE
		for i, j := 0, len(inputBytes)-1; i < j; i,j = i+1, j-1{
			inputBytes[i], inputBytes[j] = inputBytes[j], inputBytes[i]
		}

		expectedBigInt := new(big.Int).Sub(inputBigInt, big.NewInt(1))
		expectedBytes := expectedBigInt.Bytes()

		//convert BE to LE
		for i, j := 0, len(expectedBytes)-1; i < j; i,j = i+1, j-1{
			expectedBytes[i], expectedBytes[j] = expectedBytes[j], expectedBytes[i]
		}

		bitstring.ByteSubLE(inputBytes)
		require.Equal(t, expectedBytes, inputBytes)
	})
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
			output1 := bitstring.PackedBits(inputMatrix[i]).Select(j)
			output2 := bitstring.PackedBits(transposedMatrix[j]).Select(i)

			require.Equal(t,
				output1,
				output2)
		}
	}

	t.Run("Test for identity matrix", func(t *testing.T) {
		t.Parallel()

		inputMatrix := [][]byte{
			bitstring.Pack([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
			bitstring.Pack([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
			bitstring.Pack([]byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}),
			bitstring.Pack([]byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}),
			bitstring.Pack([]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}),
			bitstring.Pack([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}),
			bitstring.Pack([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}),
			bitstring.Pack([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
		}
		result, _ := bitstring.TransposePackedBits(inputMatrix)

		require.Equal(t, inputMatrix, result)
	})
	t.Run("Test for input not having rows%8==0", func(t *testing.T) {
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
	t.Run("Input must be a 2D matrix", func(t *testing.T) {
		t.Parallel()

		inputMatrix := [][]byte{
			bitstring.Pack([]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}),
			bitstring.Pack([]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}),
		}
		_, err := bitstring.TransposePackedBits(inputMatrix)
		require.Error(t, err)
	})
}

func TestToBytes32LEt(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		inputArray     int
		expectedOutput []byte
	}{
		{
			name:           "Positive Integer",
			inputArray:     123456789,
			expectedOutput: []byte{0x15, 0xCD, 0x5B, 0x07}, // Hex signed 2's complement 075BCD15
		},
		{
			name: "Negative Integer",
		    inputArray:  -123456789,
		    expectedOutput: []byte {0xEB, 0x32, 0xA4, 0xF8},// Hex signed 2's complement F8A432EB
		},
		{
			name:           "Zero",
			inputArray:     0,
			expectedOutput: []byte{0x00, 0x00, 0x00, 0x00},
		},
	}

	t.Run("Test toBytesLE", func(t *testing.T) {
		t.Parallel()

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				// inputArray := int(tc.inputArray)
				result := bitstring.ToBytesLE(tc.inputArray)
				require.Equal(t, tc.expectedOutput, result)
			})
		}
	})
}
func TestTruncateWithEllipsis(t *testing.T) {
	t.Parallel()

	inputText := []struct {
		name   string
		input  string
		output string
	}{
		{
			name:   "len(input) < max",
			input:  "Hello",
			output: "Hello",
		}, {
			name:   "len(input) = max",
			input:  "HelloWorld",
			output: "HelloWorld",
		}, {
			name:   "len(input) > max",
			input:  "Hello, World!",
			output: "Hello, Wor...(3)",
		},
	}

	maxLength := 10

	t.Run("Testing TruncateWithEllipsis", func(t *testing.T) {
		t.Parallel()

		for _, tc := range inputText {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				require.Equal(t, tc.output, bitstring.TruncateWithEllipsis(tc.input, maxLength))
			})
		}
	})
}

func TestMemclr(t *testing.T) {
	t.Parallel()

	testCase := []struct {
		name   string
		input  []int
		output []int
	}{
		{
			name:   "Case 1",
			input:  []int{1, 2, 3, 4},
			output: []int{0, 0, 0, 0},
		}, {
			name:   "Case 2",
			input:  []int{10, 20, 30, 40},
			output: []int{0, 0, 0, 0},
		}, {
			name:   "Case 3",
			input:  []int{100, 200, 300, 400},
			output: []int{0, 0, 0, 0},
		}, {
			name:   "Case 4",
			input:  []int{1000000000, 2000000000, 3000000000, 4000000000},
			output: []int{0, 0, 0, 0},
		}, {
			name:   "Case 4",
			input:  []int{},
			output: []int{},
		},
	}

	t.Run("Testing Memclr", func(t *testing.T) {
		t.Parallel()

		for _, tc := range testCase {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				bitstring.Memclr(tc.input)
				require.Equal(t, tc.output, tc.input)
			})
		}
	})
}
