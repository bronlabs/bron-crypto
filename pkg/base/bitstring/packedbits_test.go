package bitstring_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

func TestPackBits(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		inputVectors  []uint8
		expectedError error
	}{
		{
			inputVectors:  []uint8{0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0},
			expectedError: nil,
		},
		{
			inputVectors:  []uint8{0, 0, 0, 0, 0, 0, 0, 0},
			expectedError: nil,
		},
		{
			inputVectors:  []uint8{0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0},
			expectedError: nil,
		},
		{
			inputVectors:  []uint8{},
			expectedError: nil,
		},
		{
			inputVectors:  []uint8{0xAB, 0xCD},
			expectedError: errs.NewArgument("Input vector contains non-binary elements"),
		},
		{
			inputVectors:  []uint8{0x00, 0x02, 0x03, 0x04},
			expectedError: errs.NewArgument("Input vector contains non-binary elements"),
		},
	}
	for index, tc := range testCases {
		if tc.expectedError == nil {
			t.Run(fmt.Sprintf("Happy path, inputVector: %v index: %d", tc.inputVectors, index), func(t *testing.T) {
				t.Parallel()
				outputVector, err := bitstring.Pack(tc.inputVectors)
				require.NoError(t, err)
				for i := 0; i < len(tc.inputVectors); i++ {
					output := outputVector.Get(uint(i))
					require.Equal(t, tc.inputVectors[i], output)
				}
			})
		} else {
			t.Run(fmt.Sprintf("Unhappy path, inputVector: %v indexL %d", tc.inputVectors, index), func(t *testing.T) {
				t.Parallel()
				_, err := bitstring.Pack(tc.inputVectors)
				require.Error(t, err)
			})
		}
	}
}
func TestUnpackBits(t *testing.T) {
	t.Parallel()

	inputVector := bitstring.PackedBits{
		0b01001000,
		0b00101100,
		0b01101010,
		0b00011110,
		0b01011001,
		0b00111101,
		0b01111011,
		0b00001111,
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
			inputPackedBits: bitstring.PackedBits{0b00000000, 0b00001111},
			expectedOutput:  "[0 0 0 0 0 0 0 0 1 1 1 1 0 0 0 0]",
		},
		{
			inputPackedBits: bitstring.PackedBits{0b00000000, 0b00000000},
			expectedOutput:  "[0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]",
		},
		{
			inputPackedBits: bitstring.PackedBits{0b11111111, 0b11111111},
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
		0b00010010,
		0b00110100,
		0b01010110,
		0b01111000,
		0b10011010,
		0b10111100,
		0b11011110,
		0b11110000,
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
			input:          bitstring.PackedBits{0b11111111},
			i:              10,
			j:              1,
			expectedOutput: nil,
		},
		{
			input:          bitstring.PackedBits{0b11111111},
			i:              10,
			j:              -1,
			expectedOutput: nil,
		},
		{
			input:          bitstring.PackedBits{0b00000000, 0b00000000},
			i:              1,
			j:              2,
			expectedOutput: bitstring.PackedBits{0b00000000, 0b00000000},
		},
		{
			input:          bitstring.PackedBits{0b0000101, 0b0001010},
			i:              1,
			j:              2,
			expectedOutput: bitstring.PackedBits{0b0000011, 0b0001010},
		},
		{
			input:          bitstring.PackedBits{0b11100001, 0b11100100},
			i:              0,
			j:              0,
			expectedOutput: bitstring.PackedBits{0b11100001, 0b11100100},
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
		expectedOutput *uint8
	}{
		{
			input:          bitstring.PackedBits{0b11100001, 0b11100100},
			index:          20,
			expectedOutput: nil,
		},
		{
			input:          bitstring.PackedBits{0b11100001, 0b11100100},
			index:          0,
			expectedOutput: func() *uint8 { var v uint8 = 1; return &v }(),
		},
		{
			input:          bitstring.PackedBits{0b11100001, 0b11100100},
			index:          7,
			expectedOutput: func() *uint8 { var v uint8 = 1; return &v }(),
		},
		{
			input:          bitstring.PackedBits{0b11100001, 0b11100100},
			index:          15,
			expectedOutput: func() *uint8 { var v uint8 = 1; return &v }(),
		},
		{
			input:          bitstring.PackedBits{},
			index:          7,
			expectedOutput: nil,
		},
	}
	for index, tc := range testCases {
		if tc.expectedOutput != nil {
			t.Run(fmt.Sprintf("Happy Path input: %v index: %v", tc.input, index), func(t *testing.T) {
				t.Parallel()
				result := tc.input.Get(tc.index)
				require.Equal(t, *tc.expectedOutput, result)
			})
		} else {
			t.Run(fmt.Sprintf("Unhappy Path input: %v index: %v", tc.input, index), func(t *testing.T) {
				t.Parallel()
				require.Panics(t, func() { tc.input.Get(tc.index) }, "Panic should have happened")
			})
		}
	}
}

func TestGetBE(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		input          bitstring.PackedBits
		index          uint
		expectedOutput *uint8
	}{
		{
			input:          bitstring.PackedBits{0b11100001, 0b11100100},
			index:          20,
			expectedOutput: nil,
		},
		{
			input:          bitstring.PackedBits{0b11100001, 0b11100100},
			index:          0,
			expectedOutput: func() *uint8 { var v uint8 = 1; return &v }(),
		},
		{
			input:          bitstring.PackedBits{0b11100001, 0b11100100},
			index:          7,
			expectedOutput: func() *uint8 { var v uint8 = 1; return &v }(),
		},
		{
			input:          bitstring.PackedBits{0b11100001, 0b11100100},
			index:          15,
			expectedOutput: func() *uint8 { var v uint8 = 0; return &v }(),
		},
		{
			input:          bitstring.PackedBits{},
			index:          7,
			expectedOutput: nil,
		},
	}
	for index, tc := range testCases {
		if tc.expectedOutput != nil {
			t.Run(fmt.Sprintf("Happy Path input: %v index: %v", tc.input, index), func(t *testing.T) {
				t.Parallel()
				result := tc.input.GetBE(tc.index)
				require.Equal(t, *tc.expectedOutput, result)
			})
		} else {
			t.Run(fmt.Sprintf("Unhappy Path input: %v index: %v", tc.input, index), func(t *testing.T) {
				t.Parallel()
				require.Panics(t, func() { tc.input.GetBE(tc.index) }, "Panic should have happened")
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
			input:          bitstring.PackedBits{0b00000000},
			inputIndex:     1,
			expectedOutput: bitstring.PackedBits{0b00000000},
		},
		{
			input:          bitstring.PackedBits{0b10000001},
			inputIndex:     0,
			expectedOutput: bitstring.PackedBits{0b10000000},
		},
		{
			input:          bitstring.PackedBits{0b10000001},
			inputIndex:     10,
			expectedOutput: nil,
		},
		{
			input:          bitstring.PackedBits{0x01},
			inputIndex:     -1,
			expectedOutput: nil,
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
	inputVector := bitstring.PackedBits{0b00000000, 0b10101010, 0b11111111}
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
			input:          bitstring.PackedBits{0b00000000},
			expectedOutput: 8,
		},
		{
			input:          bitstring.PackedBits{0b11111111, 0b00000000},
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
		errorMessage   error
	}{
		{
			vector:         "",
			expectedOutput: nil,
			errorMessage:   errs.NewArgument("Input string cannot be empty"),
		},
		{
			vector:         "1abcd01010",
			expectedOutput: nil,
			errorMessage:   errs.NewArgument("Invalid character in the input"),
		},
		{
			vector:         "10101010",
			expectedOutput: bitstring.PackedBits{0b1010101},
			errorMessage:   nil,
		},
		{
			vector:         "0000111100001111",
			expectedOutput: bitstring.PackedBits{0b11110000, 0b11110000},
			errorMessage:   nil,
		},
		{
			vector:         "1111000011110000",
			expectedOutput: bitstring.PackedBits{0b00001111, 0b00001111},
			errorMessage:   nil,
		},
	}
	for index, tc := range testCases {
		if tc.errorMessage == nil {
			t.Run(fmt.Sprintf("Happy Path input: %v index: %d", tc.vector, index), func(t *testing.T) {
				t.Parallel()
				result, _ := bitstring.Parse(tc.vector)
				require.Equal(t, tc.expectedOutput, result)
			})
		} else {
			t.Run(fmt.Sprintf("Unhappy Path input: %v index: %d", tc.vector, index), func(t *testing.T) {
				t.Parallel()
				_, err := bitstring.Parse(tc.vector)
				require.Error(t, err)
			})
		}
	}
}
func TestTransposePackedBits(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		inputMatrix   [][]uint8
		expectedError error
	}{
		{
			inputMatrix: [][]uint8{
				{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
				{0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB},
				{0x31, 0x53, 0x75, 0x97, 0xB9, 0xDB},
				{0x41, 0x63, 0x85, 0xA7, 0xC9, 0xEB},
				{0x51, 0x73, 0x95, 0xB7, 0xD9, 0xFB},
				{0x61, 0x83, 0xA5, 0xC7, 0xE9, 0x0B},
				{0x71, 0x93, 0xB5, 0xD7, 0xF9, 0x1B},
				{0x81, 0xA3, 0xC5, 0xE7, 0x09, 0x2B},
			},
			expectedError: nil,
		},
		{
			inputMatrix: [][]uint8{
				{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
				{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
				{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
				{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00},
				{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
				{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			},
			expectedError: nil,
		},
		{
			inputMatrix: [][]byte{
				{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
				{0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB},
				{0x31, 0x53, 0x75, 0x97, 0xB9, 0xDB},
				{0x41, 0x63, 0x85, 0xA7, 0xC9, 0xEB},
				{0x51, 0x73, 0x95, 0xB7, 0xD9, 0xFB},
				{0x61, 0x83, 0xA5, 0xC7, 0xE9, 0x0B},
				{0x71, 0x93, 0xB5, 0xD7, 0xF9, 0x1B},
			},
			expectedError: errs.NewArgument("input matrix must have a number of rows divisible by 8"),
		},
		{
			inputMatrix: [][]byte{
				{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			},
			expectedError: errs.NewArgument("input matrix must be a 2D matrix"),
		},
	}

	for index, tc := range testCases {
		if tc.expectedError == nil {
			t.Run(fmt.Sprintf("Happy Path input: %v index: %d", tc.inputMatrix, index), func(t *testing.T) {
				t.Parallel()
				transposedMatrix, err := bitstring.TransposePackedBits(tc.inputMatrix)
				require.NoError(t, err)
				for i := 0; i < len(tc.inputMatrix); i++ {
					for j := 0; j < len(transposedMatrix); j++ {
						// Check that the bit at position i in the jth row of the input matrix.
						// is equal to the bit at position j in the ith row of the transposed matrix.
						// using bitstring.SelectBit (careful! it takes a byte array as input)
						output1 := bitstring.PackedBits(tc.inputMatrix[i]).Get(uint(j))
						output2 := bitstring.PackedBits(transposedMatrix[j]).Get(uint(i))

						require.Equal(t,
							output1,
							output2)
					}
				}
			})
		} else {
			t.Run(fmt.Sprintf("Unhappy Path input: %v index: %d", tc.inputMatrix, index), func(t *testing.T) {
				t.Parallel()
				_, err := bitstring.TransposePackedBits(tc.inputMatrix)
				require.Error(t, err)
			})
		}
	}
}
