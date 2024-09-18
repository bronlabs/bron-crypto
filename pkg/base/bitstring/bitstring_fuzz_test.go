package bitstring_test

import (
	"encoding/binary"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

func Fuzz_Test_SelectBit(f *testing.F) {
	f.Fuzz(func(t *testing.T, i uint, vector []byte) {
		if int(i) >= binary.Size(vector)*8 {
			t.Skip(i, vector)
		}
		bitstring.PackedBits(vector).Get(i)
	})
}
func Fuzz_Test_Transpose(f *testing.F) {
	f.Add([]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC})
	f.Fuzz(func(t *testing.T, in1 []byte, in2 []byte, in3 []byte, in4 []byte, in5 []byte, in6 []byte, in7 []byte, in8 []byte) {
		inputMatrix := [][]byte{
			in1,
			in2,
			in3,
			in4,
			in5,
			in6,
			in7,
			in8,
		}
		transposedMatrix, err := bitstring.TransposePackedBits(inputMatrix)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		for i := 0; i < len(inputMatrix); i++ {
			for j := 0; j < len(transposedMatrix); j++ {
				// Check that the bit at position i in the jth row of the input matrix.
				// is equal to the bit at position j in the ith row of the transposed matrix.
				// using bitstring.SelectBit (careful! it takes a byte array as input)
				output1 := bitstring.PackedBits(inputMatrix[i]).Get(uint(j))
				if err != nil {
					t.Skip()
				}
				output2 := bitstring.PackedBits(transposedMatrix[j][:]).Get(uint(i))
				if err != nil {
					t.Skip()
				}
				require.Equal(t,
					output1,
					output2)
			}
		}
	})
}
func FuzzToBytes32LE(f *testing.F) {
	testCases := struct {
		input []int32
	}{
		input: []int32{123456789, -123456789, 0},
	}

	for _, input := range testCases.input {
		f.Add(input)
	}

	f.Fuzz(func(t *testing.T, input int32) {
		result := bitstring.ToBytes32LE(input)

		require.Len(t, result, 4, "result should be 4 bytes long")
		backToInt := int32(binary.LittleEndian.Uint32(result))
		require.Equal(t, input, backToInt, "expected the same value as input")
	})
}
func FuzzPadToLeft(f *testing.F) {

	testCases := struct {
		inputArrays     [][]byte
		inputPadLengths []int
	}{
		inputArrays: [][]byte{
			{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			{0x21},
			{},
		},

		inputPadLengths: []int{
			0,
			1,
			4,
			-1,
		},
	}

	for _, input := range testCases.inputArrays {
		for _, padLength := range testCases.inputPadLengths {
			f.Add(input, padLength)
		}
	}

	f.Fuzz(func(t *testing.T, inBytes []byte, padLength int) {
		result := bitstring.PadToLeft(inBytes, padLength)

		require.GreaterOrEqual(t, len(result), 0)

		if padLength >= 0 {
			require.Len(t, result, len(inBytes)+padLength)

			for i := 0; i < padLength; i++ {

				require.Equal(t, byte(0), result[i], "Expected zeroed bytes for padding, found non-zero byte at index ")
			}
			require.Equal(t, inBytes, result[padLength:], "Padded result does not match the input bytes at the end")
		} else {
			require.Equal(t, inBytes, result)
		}
	})
}
func FuzzPadToRight(f *testing.F) {

	testCases := struct {
		inputArrays     [][]byte
		inputPadLengths []int
	}{
		inputArrays: [][]byte{
			{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			{0x21},
			{},
		},

		inputPadLengths: []int{
			0,
			1,
			4,
			-1,
		},
	}

	for _, input := range testCases.inputArrays {
		for _, padLength := range testCases.inputPadLengths {
			f.Add(input, padLength)
		}
	}

	f.Fuzz(func(t *testing.T, inBytes []byte, padLength int) {

		result := bitstring.PadToRight(inBytes, padLength)
		require.GreaterOrEqual(t, len(result), 0)

		if padLength > 0 {

			require.Len(t, result, len(inBytes)+padLength)
			require.Equal(t, inBytes, result[:len(inBytes)])

			for i := len(inBytes); i < len(result); i++ {
				require.Equal(t, byte(0), result[i], "Expected zeroed bytes for padding, found non-zero byte at index ")
			}
		} else {
			require.Equal(t, result, inBytes)
		}
	})
}
func FuzzTruncatewithEllipsis(f *testing.F) {

	testCases := struct {
		inputTexts []string
		maxLengths []uint
	}{
		inputTexts: []string{
			"Hello",
			"HelloWorld",
			"Hello, World!",
		},
		maxLengths: []uint{
			10,
			1,
			4,
			0,
		},
	}

	for _, text := range testCases.inputTexts {
		for _, maxLength := range testCases.maxLengths {
			f.Add(text, maxLength)
		}
	}
	f.Fuzz(func(t *testing.T, inputText string, inputMaxLength uint) {

		result := bitstring.TruncateWithEllipsis(inputText, inputMaxLength)

		if len(inputText) <= int(inputMaxLength) {
			require.Equal(t, inputText, result, "Expected result to be the same as the input.")
		} else {
			require.Equal(t, inputText[:inputMaxLength], result[:inputMaxLength], "Truncated result does not match the input bytes at the start")
			require.Equal(t, result[inputMaxLength:], fmt.Sprintf("...(%d)", (len(inputText)-int(inputMaxLength))))
		}
	})
}
func FuzzReverseBytes(f *testing.F) {

	testCases := struct {
		inputArrays [][]byte
	}{
		inputArrays: [][]byte{
			{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			{0x21, 0x43, 0x65, 0x87, 0xA9},
			{0x31, 0x53},
			{},
		},
	}

	for _, array := range testCases.inputArrays {
		f.Add(array)
	}

	f.Fuzz(func(t *testing.T, inputArray []byte) {
		result := bitstring.ReverseBytes(inputArray)

		require.Equal(t, len(inputArray), len(result), "Expected result length to be ")

		for i := 0; i < len(inputArray); i++ {
			require.Equal(t, inputArray[i], result[len(inputArray)-1-i], "Reversed result does not match the input bytes at the start")
		}
	})
}
func FuzzMemclr(f *testing.F) {
	testCases := struct {
		inputArrays [][]byte
	}{
		inputArrays: [][]byte{
			{0, 0, 0, 0},
			{1, 2, 3, 4},
			{10, 20, 30, 40},
			{},
		},
	}

	for _, array := range testCases.inputArrays {
		f.Add(array)
	}

	f.Fuzz(func(t *testing.T, inputArray []byte) {

		originalArray := make([]int, len(inputArray))
		bitstring.MemClr(inputArray)

		require.Len(t, originalArray, len(inputArray), "Expected len(result) and len(input) to be the same")

		for i := 0; i < len(inputArray); i++ {
			require.Equal(t, byte(0), inputArray[i])
		}
	})
}

func FuzzPack(f *testing.F) {
	testCases := struct {
		inputVectors [][]byte
	}{
		inputVectors: [][]byte{
			{0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0},
			{0, 0, 0, 0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0},
			{},
			{0xAB, 0xCD},
			{0x00, 0x02, 0x03, 0x04},
		},
	}

	for _, vector := range testCases.inputVectors {
		f.Add(vector)
	}

	f.Fuzz(func(t *testing.T, vector []byte) {
		input := make([]uint8, len(vector))

		outputVector, err := bitstring.Pack(input)

		require.NoError(t, err, "Invalid input")

		for i := 0; i < len(vector); i++ {
			output := outputVector.Get(uint(i))
			require.Equal(t, input[i], output)
		}
	})
}
func FuzzUnpack(f *testing.F) {
	inputVector := []byte{
		0b01001000,
		0b00101100,
		0b01101010,
		0b00011110,
		0b01011001,
		0b00111101,
		0b01111011,
		0b00001111,
	}
	f.Add(inputVector)

	f.Fuzz(func(t *testing.T, vector []byte) {
		inputVector := bitstring.PackedBits(vector)
		outputVector := inputVector.Unpack()

		for i := 0; i < len(inputVector)*8; i++ {
			input := inputVector.Get(uint(i))
			require.Equal(t, input, outputVector[i])
		}
	})
}
func FuzzString(f *testing.F) {
	testCases := struct {
		inputPackedBits [][]byte
	}{
		inputPackedBits: [][]byte{
			{},
			{0b00000000, 0b00001111},
			{0b00000000, 0b00000000},
			{0b11111111, 0b11111111},
		},
	}
	for _, input := range testCases.inputPackedBits {
		f.Add(input)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		inputPacledBits := bitstring.PackedBits(input)
		result := inputPacledBits.String()

		require.Equal(t, inputPacledBits.BitLen(), (8 * len(inputPacledBits)))

		unpackedInput := inputPacledBits.Unpack()
		for i := len(result) - 1; i <= 0; i-- {
			require.Equal(t, result[i], unpackedInput[i])
		}
	})
}

func FuzzSwap(f *testing.F) {

	testCases := struct {
		input [][]byte
		i, j  []uint
	}{
		input: [][]byte{
			{},
			{0b11111111},
			{0b00000000},
			{0b11111111},
			{0b00000011, 0b00010010},
			{0b11100001, 0b11100100},
		},
		i: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 67},
		j: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 99},
	}
	for _, input := range testCases.input {
		for _, i := range testCases.i {
			for _, j := range testCases.j {
				f.Add(input, i, j)
			}
		}
	}

	f.Fuzz(func(t *testing.T, input []byte, i uint, j uint) {
		if int(i) >= len(input) || int(j) >= len(input) || len(input) == 0 {
			t.Skip() // Panics
		}
		if i == j {
			inputPackedBits := bitstring.PackedBits(input)
			originalCopy := slices.Clone(inputPackedBits)
			inputPackedBits.Swap(i, j)
			require.Equal(t, inputPackedBits, originalCopy, "should return with no change")
		}
		inputPackedBits := bitstring.PackedBits(input)
		originalCopy := slices.Clone(inputPackedBits)
		inputPackedBits.Swap(i, j)

		require.Equal(t, inputPackedBits.BitLen(), originalCopy.BitLen())

		unpackedInput := inputPackedBits.Unpack()
		unpackedOriginalCopy := originalCopy.Unpack()

		for index := 0; index < len(unpackedOriginalCopy); index++ {
			if index == int(i) || index == int(j) {
				require.Equal(t, unpackedOriginalCopy[j], unpackedInput[i])
				require.Equal(t, unpackedOriginalCopy[i], unpackedInput[j])

			} else {
				require.Equal(t, unpackedOriginalCopy[index], unpackedInput[index])
			}
		}
	})
}
func FuzzGet(f *testing.F) {

	testCases := struct {
		input       [][]byte
		inputIndexs []uint
	}{
		input: [][]byte{
			{},
			{0b11100001, 0b11100001},
			{0b11100001, 0b11100100},
			{0b11100001, 0b11111100},
			{0b11100001},
		},
		inputIndexs: []uint{0, 1, 2, 3, 4, 85},
	}
	for _, input := range testCases.input {
		for _, index := range testCases.inputIndexs {
			f.Add(input, index)
		}
	}

	f.Fuzz(func(t *testing.T, input []byte, index uint) {
		if int(index) < len(input) {
			inputPackedBits := bitstring.PackedBits(input)
			output := inputPackedBits.Get(index)
			unpackedInput := inputPackedBits.Unpack()

			require.Equal(t, unpackedInput[index], output)
		}
	})
}
func FuzzRepeatBits(f *testing.F) {
	inputVector := []byte{0b00000000, 0b10101010, 0b11111111}
	inputRepetition := []uint{0, 1, 2, 3, 4, 85}

	for _, repetition := range inputRepetition {
		f.Add(inputVector, repetition)
	}

	f.Fuzz(func(t *testing.T, input []byte, repetition uint) {
		inputPackedBits := bitstring.PackedBits(input)
		outputVector := inputPackedBits.Repeat(int(repetition))

		for i := 0; i < len(inputPackedBits)*8; i++ {
			for j := 0; j < int(repetition); j++ {
				output := outputVector.Get(uint((i*int(repetition) + j)))
				input := inputPackedBits.Get(uint(i))
				require.Equal(t, input, output)
			}
		}
	})
}
func FuzzBitLen(f *testing.F) {
	testCases := struct {
		input [][]byte
	}{
		input: [][]byte{
			{0b00000000},
			{0b11111111, 0b00000000},
			{},
		},
	}
	for _, input := range testCases.input {
		f.Add(input)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		inputPackedBits := bitstring.PackedBits(input)
		result := inputPackedBits.BitLen()
		require.Equal(t, 8*len(inputPackedBits), result)
	})
}
func FuzzParse(f *testing.F) {
	testCases := struct {
		inputVectors []string
	}{
		inputVectors: []string{
			"",
			"1abcd01010",
			"10101010",
			"0000111100001111",
			"1111000011110000",
		},
	}
	for _, vector := range testCases.inputVectors {
		f.Add(vector)
	}

	f.Fuzz(func(t *testing.T, vector string) {
		result, err := bitstring.Parse(vector)

		if err != nil {
			require.Error(t, err, "Invalid input")
		} else {
			result.Unpack()
			for i := len(vector) - 1; i < -1; i-- {
				require.Equal(t, vector[i], result[i])
			}
		}
	})
}
