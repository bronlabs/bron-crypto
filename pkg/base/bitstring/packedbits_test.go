package bitstring_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
)

func TestPackBits(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		inputVectors [][]uint8
	}{
		{
			inputVectors: [][]uint8{
				{0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0},
				{0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0},
				{},
				{0xAB, 0xCD},
				{0x00, 0x02, 0x03, 0x04},
			},
		},
	}
	for index, tc := range testCases {
		for _, vector := range tc.inputVectors {
			outputVector, err := bitstring.Pack(vector)
			if err == nil {
				t.Run(fmt.Sprintf("Happy path, inputVector: %v index: %d", vector, index), func(t *testing.T) {
					t.Parallel()
					for i := 0; i < len(vector); i++ {
						output := outputVector.Get(uint(i))
						require.Equal(t, vector[i], output)
					}
				})
			} else {
				t.Run(fmt.Sprintf("Unhappy path, inputVector: %v indexL %d", vector, index), func(t *testing.T) {
					t.Parallel()
					require.Error(t, err)
				})
			}
		}
	}
}
func TestUnpackBits(t *testing.T) {
	t.Parallel()
	inputVector := bitstring.PackedBits{
		0b01001000, 0b00101100,
		0b01101010, 0b00011110,
		0b01011001, 0b00111101,
		0b01111011, 0b00001111,
	}
	outputVector := inputVector.Unpack()
	for i := 0; i < len(inputVector)*8; i++ {
		input := inputVector.Get(uint(i))
		require.Equal(t, input, outputVector[i])
	}
}
func TestString(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		inputPackedBits bitstring.PackedBits
		expectedOutput  string
	}{
		{
			inputPackedBits: bitstring.PackedBits{},
			expectedOutput:  "[]",
		},
		{
			inputPackedBits: bitstring.PackedBits{0x00, 0x0F},
			expectedOutput:  "[0 0 0 0 0 0 0 0 1 1 1 1 0 0 0 0]",
		},
		{
			inputPackedBits: bitstring.PackedBits{0x00, 0x00},
			expectedOutput:  "[0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
		},
		{
			inputPackedBits: bitstring.PackedBits{0xFF, 0xFF},
			expectedOutput:  "[1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1]",
		},
	}
	for index, tc := range testCases {
		t.Run(fmt.Sprintf("Happy path, input: %v, index: %d", tc.inputPackedBits, index), func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expectedOutput, tc.inputPackedBits.String())
		})
	}
}
func TestSelectBit(t *testing.T) {
	t.Parallel()
	inputVector := bitstring.PackedBits{
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
		output := inputVector.Get(uint(i))
		require.Equalf(t, expectedVector[i], output, "i=%d", i)
	}
}

func TestSwap(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		input          bitstring.PackedBits
		i, j           int
		expectedOutput bitstring.PackedBits
	}{
		{
			input:          bitstring.PackedBits{0xFF},
			i:              10,
			j:              1,
			expectedOutput: bitstring.PackedBits{0xFF},
		},
		{
			input:          bitstring.PackedBits{0xFF},
			i:              10,
			j:              -1,
			expectedOutput: bitstring.PackedBits{0xFF},
		},
		{
			input:          bitstring.PackedBits{0xFF, 0xFF},
			i:              1,
			j:              2,
			expectedOutput: bitstring.PackedBits{0xFF, 0xFF},
		},
		{
			input:          bitstring.PackedBits{0x00, 0x00},
			i:              1,
			j:              2,
			expectedOutput: bitstring.PackedBits{0x00, 0x00},
		},
		{
			input:          bitstring.PackedBits{0xAb, 0x00},
			i:              0,
			j:              0,
			expectedOutput: bitstring.PackedBits{0xAb, 0x00},
		},
	}

	for index, tc := range testCases {
		if tc.i < tc.input.BitLen() && tc.j < tc.input.BitLen() && (tc.i >= 0 || tc.j >= 0) {
			t.Run(fmt.Sprintf("Happy Path input: %v index: %d", tc.input, index), func(t *testing.T) {
				t.Parallel()
				tc.input.Swap(uint(tc.i), uint(tc.j))
				require.Equal(t, tc.expectedOutput, tc.input)
			})
		} else {
			t.Run(fmt.Sprintf("Unhappy Path input: %v index: %d", tc.input, index), func(t *testing.T) {
				t.Parallel()
				require.Panics(t, func() { tc.input.Swap(uint(tc.i), uint(tc.j)) }, "Panic")
			})
		}
	}
}
func TestGet(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		input          bitstring.PackedBits
		index          uint
		expectedOutput uint8
	}{
		{
			input:          bitstring.PackedBits{0x12, 0x13},
			index:          20,
			expectedOutput: 0,
		},
		{
			input:          bitstring.PackedBits{0x12},
			index:          0,
			expectedOutput: 0,
		},
		{
			input:          bitstring.PackedBits{0x12, 0x00, 0xFF},
			index:          7,
			expectedOutput: 0,
		},
		{
			input:          bitstring.PackedBits{},
			index:          7,
			expectedOutput: 0,
		},
	}
	for index, tc := range testCases {
		if int(tc.index) <= tc.input.BitLen() {
			t.Run(fmt.Sprintf("Happy Path input: %v index: %v", tc.input, index), func(t *testing.T) {
				t.Parallel()
				result := tc.input.Get(tc.index)
				require.Equal(t, tc.expectedOutput, result)
			})
		} else {
			t.Run(fmt.Sprintf("Unhappy Path input: %v index: %v", tc.input, index), func(t *testing.T) {
				t.Parallel()
				require.Panics(t, func() { tc.input.Get(tc.index) }, "Panic should have happened")
			})
		}
	}
}

func TestUnSet(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		input          bitstring.PackedBits
		inputIndex     int
		expectedOutput bitstring.PackedBits
	}{
		{
			input:          bitstring.PackedBits{0x00},
			inputIndex:     1,
			expectedOutput: bitstring.PackedBits{0x00},
		},
		{
			input:          bitstring.PackedBits{0x01},
			inputIndex:     0,
			expectedOutput: bitstring.PackedBits{0x00},
		},
		{
			input:      bitstring.PackedBits{0x01},
			inputIndex: 10,
			// the function should panic
		},
		{
			input:      bitstring.PackedBits{0x01},
			inputIndex: -1,
			// the function should panic
		},
	}
	for index, tc := range testCases {
		if tc.inputIndex >= 0 && tc.inputIndex < tc.input.BitLen() {
			t.Run(fmt.Sprintf("Happy Path input: %v index: %d", tc.input, index), func(t *testing.T) {
				t.Parallel()
				tc.input.Clear(uint(tc.inputIndex))

				require.Equal(t, tc.expectedOutput, tc.input)
			})
		} else {
			t.Run(fmt.Sprintf("Unhappy Path input: %v index: %d", tc.input, index), func(t *testing.T) {
				t.Parallel()
				require.Panics(t, func() { tc.input.Clear(uint(tc.inputIndex)) }, "Should cause a panic")
			})
		}
	}
}

func TestRepeatBits(t *testing.T) {
	t.Parallel()
	inputVector := bitstring.PackedBits{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}
	for nRepetitions := 1; nRepetitions < 8; nRepetitions++ {
		outputVector := inputVector.Repeat(nRepetitions)
		for i := 0; i < len(inputVector)*8; i++ {
			for j := 0; j < nRepetitions; j++ {
				output := outputVector.Get(uint(i*nRepetitions + j))
				input := inputVector.Get(uint(i))
				require.Equalf(t, input, output, "i=%d, j=%d", i, j)
			}
		}
	}
}

func TestBitLen(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		input          bitstring.PackedBits
		expectedOutput int
	}{
		{
			input:          bitstring.PackedBits{0x00},
			expectedOutput: 8,
		},
		{
			input:          bitstring.PackedBits{0xFF, 0x00},
			expectedOutput: 16,
		},
		{
			input:          bitstring.PackedBits{},
			expectedOutput: 0,
		},
	}
	for index, tc := range testCases {
		t.Run(fmt.Sprintf("Happy Path input: %v index: %d", tc.input, index), func(t *testing.T) {
			t.Parallel()
			result := tc.input.BitLen()
			require.Equal(t, tc.expectedOutput, result)
		})
	}
}

func TestParse(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		vector         string
		expectedOutput bitstring.PackedBits
		errorMessage   string
	}{
		{
			vector:         "",
			expectedOutput: nil,
			errorMessage:   "Input string cannot be empty",
		},
		{
			vector:         "1abcd01010",
			expectedOutput: nil,
			errorMessage:   "Input string cannot be empty",
		},
		{
			vector:         "01010101",
			expectedOutput: bitstring.PackedBits{0x55},
			errorMessage:   "",
		},
		{
			vector:         "1111000011110000",
			expectedOutput: bitstring.PackedBits{0xF0, 0xF0},
			errorMessage:   "",
		},
	}
	for index, tc := range testCases {
		if tc.errorMessage == "" {
			t.Run(fmt.Sprintf("Happy Path input: %v index: %d", tc.vector, index), func(t *testing.T) {
				t.Parallel()
				result, _ := bitstring.Parse(tc.vector)
				require.Equal(t, tc.expectedOutput, result)
			})
		} else {
			t.Run(fmt.Sprintf("Unhappy Path input: %v index: %d", tc.vector, index), func(t *testing.T) {
				t.Parallel()
				_, err := bitstring.Parse(tc.vector)
				require.Error(t, err, tc.errorMessage)
			})

		}
	}
}
