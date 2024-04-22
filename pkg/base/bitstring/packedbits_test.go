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

	inputVectorsArray := [][]byte{
		{0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0},
		{},
		{0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0},
		{0xAB},
	}

	// errorsArray := []error{
	// 	nil,
	//     errs.NewArgument("Input vector contains non-binary elements"),
	// }

	for _, vector := range inputVectorsArray {
		outputVector, err := bitstring.Pack(vector)
		t.Run("After packing, output[index] should be equal to inputVetor[index]", func(t *testing.T) {
			t.Parallel()

			if err != nil {
				require.Error(t, err)
			} else {
				for i := 0; i < len(vector); i++ {
					output := outputVector.Get(uint(i))

					require.Equal(t, vector[i], output)
				}
			}
		})
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
		name            string
		inputPackedBits bitstring.PackedBits
		expectedOutput  string
	}{
		{
			name:            "Unpacking an empty PackedBits is should return an empty string",
			inputPackedBits: bitstring.PackedBits{},
			expectedOutput:  "[]",
		},
		{
			name:            "Testing with two bits",
			inputPackedBits: bitstring.PackedBits{0x00, 0x0F},
			expectedOutput:  "[0 0 0 0 0 0 0 0 1 1 1 1 0 0 0 0]",
		},
		{
			name:            "Testing with three bits",
			inputPackedBits: bitstring.PackedBits{0xF0, 0x0F, 0x00},
			expectedOutput:  "[0 0 0 0 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0]",
		},
	}

	for index, tc := range testCases {
		t.Run(fmt.Sprintf("testCase: %s input: %v index: %v", tc.name, tc.inputPackedBits, index), func(t *testing.T) {
			t.Parallel()

			result := tc.inputPackedBits.String()
			require.Equal(t, tc.expectedOutput, result)
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
		name           string
		pd             bitstring.PackedBits
		i, j           int
		expectedOutput bitstring.PackedBits
	}{
		{
			name:           "Any index out of range should cause a panic",
			pd:             bitstring.PackedBits{0xFF},
			i:              10,
			j:              1,
			expectedOutput: bitstring.PackedBits{0xFF},
		},
		{
			name:           "Swapping any two bits in an all zero vector should return the same vector",
			pd:             bitstring.PackedBits{0x00},
			i:              1,
			j:              2,
			expectedOutput: bitstring.PackedBits{0x00},
		},
		{
			name:           "Swapping a bit with itself should not change the input",
			pd:             bitstring.PackedBits{0xAb},
			i:              0,
			j:              0,
			expectedOutput: bitstring.PackedBits{0xAb},
		},
	}

	for index, tc := range testCases {
		t.Run(fmt.Sprintf("TestCase: %s input: %v index: %v", tc.name, tc.pd, index), func(t *testing.T) {
			t.Parallel()

			if tc.i > 7 || tc.j > 7 {
				require.Panics(t, func() { tc.pd.Swap(uint(tc.i), uint(tc.j)) }, "error")
			} else {
				tc.pd.Swap(uint(tc.i), uint(tc.j))
				require.Equal(t, tc.expectedOutput, tc.pd)
			}
		})
	}
}

func TestGet(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		pd             bitstring.PackedBits
		index          uint
		expectedOutput uint8
	}{
		{
			name:           "Selecting an out of bounds index to make sure a Panic happens",
			pd:             bitstring.PackedBits{0x12, 0x13},
			index:          20,
			expectedOutput: 0,
		},
		{
			name:           "Getting the first index of {0x12} and to get 0 in return",
			pd:             bitstring.PackedBits{0x12},
			index:          0,
			expectedOutput: 0,
		},
		{
			name:           "Getting the 7th index of {0x12} and to get 1 in return",
			pd:             bitstring.PackedBits{0x12},
			index:          7,
			expectedOutput: 0,
		},
	}
	for index, tc := range testCases {
		t.Run(fmt.Sprintf("TestCase: %s input: %v index: %v", tc.name, tc.pd, index), func(t *testing.T) {
			t.Parallel()

			if int(tc.index) > 7*len(tc.pd) {
				require.Panics(t, func() { tc.pd.Get(tc.index) }, "Panic should have happened")
			} else {
				result := tc.pd.Get(tc.index)
				require.Equal(t, tc.expectedOutput, result)
			}
		})
	}
}

func TestUnSet(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		pd             bitstring.PackedBits
		inputIndex     int
		expectedOutput bitstring.PackedBits
	}{
		{
			name:           "Changing any bit to zero in 0x00 should result in 0x00",
			pd:             bitstring.PackedBits{0x00},
			inputIndex:     1,
			expectedOutput: bitstring.PackedBits{0x00},
		},
		{
			name:           "Changing the index 0 of 0x01 should result in 0x00",
			pd:             bitstring.PackedBits{0x01},
			inputIndex:     0,
			expectedOutput: bitstring.PackedBits{0x00},
		},
		{
			name:       "Attempting to unset any index out of range should result in a panic",
			pd:         bitstring.PackedBits{0x01},
			inputIndex: 10,
			// the function should panic
		},
	}
	for index, tc := range testCases {
		t.Run(fmt.Sprintf("TestCase: %s input: %v indexIndex: %d index: %d", tc.name, tc.pd, tc.inputIndex, index), func(t *testing.T) {
			t.Parallel()

			if tc.inputIndex > len(tc.pd) {

				require.Panics(t, func() { tc.pd.Clear(uint(tc.inputIndex)) }, "Should casue a panic")

			} else {
				tc.pd.Clear(uint(tc.inputIndex))

				require.Equal(t, tc.expectedOutput, tc.pd)
			}
		})
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
		name           string
		pd             bitstring.PackedBits
		expectedOutput int
	}{
		{
			name:           "Single element PackedBits should have a length of 8",
			pd:             bitstring.PackedBits{0x00},
			expectedOutput: 8,
		}, {
			name:           "PackedBits with two elements should have a length of 8",
			pd:             bitstring.PackedBits{0xFF, 0x00},
			expectedOutput: 16,
		},
		{
			name:           "an empty PackedBits would have a length of zero",
			pd:             bitstring.PackedBits{},
			expectedOutput: 0,
		},
	}

	for index, tc := range testCases {
		t.Run(fmt.Sprintf("TestCase: %s input: %v index: %d", tc.name, tc.pd, index), func(t *testing.T) {
			t.Parallel()

			result := tc.pd.BitLen()

			require.Equal(t, tc.expectedOutput, result)
		})
	}
}

func TestParse(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		vector         string
		expectedOutput bitstring.PackedBits
		expectedError  error
	}{
		{
			name:           "an empty string could result in an error an nil return",
			vector:         "",
			expectedOutput: nil,
			expectedError:  errs.NewArgument("Input string cannot be empty"),
		},
		{
			name:           "an empty string could result in an error an nil return",
			vector:         "1abcd01010",
			expectedOutput: nil,
			expectedError:  errs.NewArgument("Invalid character in the input"),
		},
		{
			name:           "representation of hexadecimal of 0x55 in decimal",
			vector:         "01010101",
			expectedOutput: bitstring.PackedBits{0x55},
			expectedError:  nil,
		},
		{
			name:           "representation of hexadecimal of 0xF0,0xF0 in decimal",
			vector:         "1111000011110000",
			expectedOutput: bitstring.PackedBits{0xF0, 0xF0},
			expectedError:  nil,
		},
	}

	for index, tc := range testCases {
		t.Run(fmt.Sprintf("Testcase: %s index: %d", tc.vector, index), func(t *testing.T) {
			t.Parallel()

			result, _ := bitstring.Parse(tc.vector)

			require.Equal(t, tc.expectedOutput, result)
		})
	}
}
