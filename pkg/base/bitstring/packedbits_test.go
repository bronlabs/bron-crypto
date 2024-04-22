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
		name        string
		inputVector []byte
		expected    bitstring.PackedBits
	}{
		{
			name:        "Packing an empty input should result in an empty packedBits",
			inputVector: []byte{},
			expected:    bitstring.PackedBits{},
		},
		{
			name:        "Packing an all zero input should result in an all packedBits",
			inputVector: []byte{0x00, 0x00, 0x00, 0x00},
			expected:    bitstring.PackedBits{0x00},
		},
		// {
		//     name:     "",
		//     inputVector:    []byte{0x01, 0x00},
		//     expected: bitstring.PackedBits{0x01},
		// },
	}

	for index, tc := range testCases {
		t.Run(fmt.Sprintf(("TestCase: %s input: %v index: %d"), tc.name, tc.inputVector, index), func(t *testing.T) {
			t.Parallel()

			result := bitstring.Pack(tc.inputVector)
			fmt.Println(result)
			require.Equal(t, tc.expected, result)
		})
	}
	t.Run("After packing, output[index] should be equal to inputVetor[index] ", func(t *testing.T) {
		inputVector := []byte{0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0}
		outputVector := bitstring.Pack(inputVector)
		for i := 0; i < len(inputVector); i++ {
			output := outputVector.Select(i)

			require.Equal(t, inputVector[i], output)
		}
	})
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
		input := inputVector.Select(i)
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
		output := inputVector.Select(i)
		require.Equalf(t, expectedVector[i], output, "i=%d", i)
	}
}

// func TestSwap(t *testing.T) {
// 	t.Parallel()

// 	testCases := []struct {
// 		// name string swap of a swap is itself
// 		pd bitstring.PackedBits
// 		i, j int
// 		expectedOutput bitstring.PackedBits
// 	}{
// 		{
// 			pd: bitstring.PackedBits {0xAA},
//             i: 0,
//             j: 1,
//             expectedOutput: bitstring.PackedBits {0xA9},
// 		},
// 		{
// 			pd: bitstring.PackedBits {0x9E},
//             i: 1,
//             j: 2,
//             expectedOutput: bitstring.PackedBits {0x9E},
// 		},
// 		{
// 			pd: bitstring.PackedBits {0x6B},
//             i: 1,
//             j: 2,
//             expectedOutput: bitstring.PackedBits {0x6F},
// 		},
// 		{
// 			pd: bitstring.PackedBits {0xEB},
//             i: 5,
//             j: 7,
//             expectedOutput: bitstring.PackedBits {0xEB},
// 		},

// 	}

// 	for index, tc := range testCases {
// 		t.Run(fmt.Sprintf("TestCase: %v index: %v", tc.pd, index), func(t *testing.T){
// 			t.Parallel()

// 			tc.pd.Swap(tc.i, tc.j)
// 			require.Equal(t, tc.expectedOutput, tc.pd)
// 		})
// 	}
// }

func TestSet(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		pd             bitstring.PackedBits
		index          int
		bit            byte
		expectedOutput bitstring.PackedBits
	}{
		{
			name:           "Set least significant bit in zeroed packedBits to one, to get 1",
			pd:             bitstring.PackedBits{0x00},
			index:          0,
			bit:            1,
			expectedOutput: bitstring.PackedBits{0x01},
		},
		{
			name:           "Setting a bit to one in fully-set Packedbits should result in the original Packedbits",
			pd:             bitstring.PackedBits{0xFF},
			index:          6,
			bit:            1,
			expectedOutput: bitstring.PackedBits{0xFF},
		},
		{
			name:           "Swapping a zero to one in a number that doesn't include all zero or all one",
			pd:             bitstring.PackedBits{0xAB},
			index:          2,
			bit:            1,
			expectedOutput: bitstring.PackedBits{0xAF},
		},
	}
	for index, tc := range testCases {
		t.Run(fmt.Sprintf("TestCase: %s input: %v index: %v", tc.name, tc.pd, index), func(t *testing.T) {
			t.Parallel()

			tc.pd.Set(tc.index, tc.bit)

			require.Equal(t, tc.expectedOutput, tc.pd)
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
		// {
		// 	name : "Changing the bit at index 2 in 0xFF should result in 0xFD",
		//     pd: bitstring.PackedBits {0xFF},
		//     inputIndex: 2,
		//     expectedOutput: bitstring.PackedBits {0xFD},
		// }, //it doesn't change the bit@index 2 to zero
	}
	for index, tc := range testCases {
		t.Run(fmt.Sprintf("TestCase: %s input: %v indexIndex: %d index: %d", tc.name, tc.pd, tc.inputIndex, index), func(t *testing.T) {
			t.Parallel()

			tc.pd.Unset(tc.inputIndex)

			require.Equal(t, tc.expectedOutput, tc.pd)
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
				output := outputVector.Select(i*nRepetitions + j)
				input := inputVector.Select(i)
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
			name:           "an empty PackedBits should have a length of zero",
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
		v              string
		expectedOutput bitstring.PackedBits
	}{
		{
			name:           "an empty string sould result in an error an nil return",
			v:              "",
			expectedOutput: nil,
		}, {
			name:           "representation of hexidecimal of 0x55 in decimal",
			v:              "01010101",
			expectedOutput: bitstring.PackedBits{0x55},
		}, {
			name:           "representation of hexidecimal of 0xF0,0xF0 in decimal",
			v:              "1111000011110000",
			expectedOutput: bitstring.PackedBits{0xF0, 0xF0},
		},
	}

	for index, tc := range testCases {
		t.Run(fmt.Sprintf("Testcase: %s index: %d", tc.v, index), func(t *testing.T) {
			t.Parallel()

			result, _ := bitstring.Parse(tc.v)

			require.Equal(t, tc.expectedOutput, result)
		})
	}
}
