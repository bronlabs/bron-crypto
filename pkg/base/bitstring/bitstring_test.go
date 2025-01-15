package bitstring_test

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/bitstring"
)

func TestReverseBytes(t *testing.T) {
	t.Parallel()

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

func TestToBytes32LEt(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		inputArray     int32
		expectedOutput []byte
	}{
		{
			name:       "Positive Integer",
			inputArray: 123456789,
		},
		{
			name:       "Neagative Integer",
			inputArray: -123456789,
		},
		{
			name:       "Zero",
			inputArray: 0,
		},
	}

	for index, tc := range testCases {
		t.Run(fmt.Sprintf("Convertig to bytes and reverting back to int should give us the same input input: %v index: %d", tc.inputArray, index), func(t *testing.T) {
			t.Parallel()

			result := bitstring.ToBytes32LE(tc.inputArray)
			backToInt := binary.LittleEndian.Uint32(result)
			require.Equal(t, tc.inputArray, int32(backToInt))
		})
	}
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

	maxLength := uint(10)

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

			bitstring.MemClr(tc.input)
			require.Equal(t, tc.output, tc.input)
		})
	}
}
