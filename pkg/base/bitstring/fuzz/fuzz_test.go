package fuzz

import (
	"bytes"
	"encoding/binary"
	"fmt"

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
		bitstring.PackedBits(vector).Select(int(i)) 
		// bitstring.PackedBits(vector).Get(i) // need to be changed after packedBits is updated
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
				output1 := bitstring.PackedBits(inputMatrix[i]).Select((j))
				// output1 := bitstring.PackedBits(inputMatrix[i]).Get(uint(j)) // after after packedBits update
				if err != nil {
					t.Skip()
				}
				output2 := bitstring.PackedBits(transposedMatrix[j][:]).Select((i))
				// output2 := bitstring.PackedBits(transposedMatrix[j][:]).Get(uint(i)) // after after packedBits update
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

	for _,input := range testCases.input {
		f.Add(input)
	}

	f.Fuzz(func(t *testing.T, input int32) {
		result := bitstring.ToBytes32LE(input)

		if len(result) != 4 {
			require.Len(t, result, 4, "result should be 4 bytes long")
		}

		backToInt := int32(binary.LittleEndian.Uint32(result))

		if backToInt != input{
			require.Equal(t, input, backToInt, "expected the same value as original")
		}
    })
}

func FuzzPadToLeft(f *testing.F){

	testCases := struct {
		inputArrays [][]byte
		inputPadLengths []int
	}{
		inputArrays: [][]byte{
			{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			{0x21},
			{},
		},
	
		inputPadLengths:  []int{
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

		if padLength <= 0 && !bytes.Equal(result, inBytes){
			require.Equal(t, inBytes, result, "Expected result to be the same as the input, but it was not ")
		}
		if padLength > 0 {
            if len(result) != len(inBytes) + padLength {
				require.Len(t, result, len(inBytes), "Expected result length to be ") // len(inBytes) + padLength)
			}
			for i:= 0; i < padLength; i++ {
				if result[i] != 0 {
					require.Equal(t, byte(0), result[i],"Expected zeroed bytes for padding, found non-zero byte at index ")
				}
			}
			if !bytes.Equal(result[padLength: ], inBytes) {
				require.Equal(t, inBytes, result[padLength:],"Padded result does not match the input bytes at the end")
			}
		}
	})
}

func FuzzPadToRight(f *testing.F){

	testCases := struct {
		inputArrays [][]byte
		inputPadLengths []int
	}{
		inputArrays: [][]byte{
			{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
			{0x21},
			{},
		},
	
		inputPadLengths:  []int{
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

		if padLength <= 0{
			require.Equal(t, inBytes, result, "Expected result to be the same as the input, but it was not ")
		}
		if padLength > 0 {
            if len(result) != len(inBytes) + padLength {
				require.Len(t, result, len(inBytes), "Expected result length to be ") // len(inBytes) + padLength)
			}
			if !bytes.Equal(result[:len(inBytes)], inBytes) {
				require.Equal(t, inBytes, result[padLength:],"Padded result does not match the input bytes at the start")
			}
			for i:= len(inBytes); i < len(result); i++ {
				if result[i] != 0 {
					require.Equal(t, byte(0), result[i],"Expected zeroed bytes for padding, found non-zero byte at index ")
				}
			}
		}
	})
}

func FuzzTruncatewithEllipsis(f *testing.F){

	testCases := struct {
		inputTexts []string
		maxLengths []int
	}{
		inputTexts: []string {
			"Hello",
			"HelloWorld",
			"Hello, World!",
		},
		maxLengths:  []int{
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

	f.Fuzz(func(t *testing.T, inputText string, inputMaxLength int){
		result := bitstring.TruncateWithEllipsis(inputText, inputMaxLength)

		if len(inputText) <= inputMaxLength {
			require.Equal(t, inputText, result, "Expected result to be the same as the input, but it was not ")
		} else {
			if inputText[:inputMaxLength] != result[:inputMaxLength] {
				require.Equal(t, inputText[:inputMaxLength], result[:inputMaxLength],"Truncated result does not match the input bytes at the start")
			}
			if result[inputMaxLength:] != fmt.Sprintf("...(%d)",(len(inputText)-inputMaxLength)) {
				require.Equal(t, result[inputMaxLength-1:], fmt.Sprintf("...(%d)",(len(inputText)-inputMaxLength)))
			}
		}
	})
}

func FuzzReverseBytes(f *testing.F){

	testCases := struct {
		inputArrays [][]byte
		inputPadLengths []int
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

		if len(inputArray) != len(result) {
			require.Equal(t, len(inputArray), len(result), "Expected result length to be ")
		}
		if len(inputArray) == 0 {
			require.Equal(t, inputArray, result, "Expected result to be an empty array ")
		}
		for i := 0; i < len(inputArray); i++ {
			if inputArray[i] != result[len(inputArray)-1-i] {
				require.Equal(t, inputArray[i], result[len(inputArray)-1-i],"Reversed result does not match the input bytes at the start")
			}
		}
	})
}

func FuzzMemclr(f *testing.F){ 
	testCases := struct {
		inputArrays [][]int
	}{
		inputArrays: [][]int{
			{1, 2, 3, 4},
			{1, 2, 3, 4},
			{1, 2, 3, 4},
			{},
		},
	}

	for _, array := range testCases.inputArrays {
            f.Add(array)
    }

	f.Fuzz(func(t *testing.T, inputArray []int) { // fuzzing can't take this inputType
		originalArray := make([]int, len(inputArray))
		bitstring.Memclr(inputArray)

		if len(inputArray)!= len(originalArray) {
			require.Equal(t, len(originalArray), len(inputArray), "Expected len(result) and len(input) to be the same")
		}

		for i := 0; i < len(inputArray); i++ {
            if inputArray[i] != 0 {
                require.Equal(t, inputArray[i], 0 ,"Memclr result does not match the input bytes at the start")
            }
        }
	})
}

// func Fuzz_Test_SelectBit(f *testing.F) {
// 	f.Fuzz(func(t *testing.T, i uint, vector []byte) {
// 		if int(i) >= binary.Size(vector)*8 {
// 			t.Skip(i, vector)
// 		}
// 		bitstring.PackedBits(vector).Get(i)
// 	})
// }

// func Fuzz_Test_Transpose(f *testing.F) {
// 	f.Add([]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC})
// 	f.Fuzz(func(t *testing.T, in1 []byte, in2 []byte, in3 []byte, in4 []byte, in5 []byte, in6 []byte, in7 []byte, in8 []byte) {
// 		inputMatrix := [][]byte{
// 			in1,
// 			in2,
// 			in3,
// 			in4,
// 			in5,
// 			in6,
// 			in7,
// 			in8,
// 		}
// 		transposedMatrix, err := bitstring.TransposePackedBits(inputMatrix)
// 		if err != nil && !errs.IsKnownError(err) {
// 			require.NoError(t, err)
// 		}
// 		if err != nil {
// 			t.Skip()
// 		}
// 		for i := 0; i < len(inputMatrix); i++ {
// 			for j := 0; j < len(transposedMatrix); j++ {
// 				// Check that the bit at position i in the jth row of the input matrix.
// 				// is equal to the bit at position j in the ith row of the transposed matrix.
// 				// using bitstring.SelectBit (careful! it takes a byte array as input)
// 				output1 := bitstring.PackedBits(inputMatrix[i]).Get(uint(j))
// 				if err != nil {
// 					t.Skip()
// 				}
// 				output2 := bitstring.PackedBits(transposedMatrix[j][:]).Get(uint(i))
// 				if err != nil {
// 					t.Skip()
// 				}
// 				require.Equal(t,
// 					output1,
// 					output2)
// 			}
// 		}
// 	})
// }

// func FuzzPackBits(f *testing.F) {
// 	testCases := []struct {
// 		inputVectors [][]uint8
// 	}{
// 		{
// 			inputVectors: [][]uint8{
// 				{0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0},
// 				{0, 0, 0, 0, 0, 0, 0, 0},
// 				{0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0},
// 				{},
// 				{0xAB, 0xCD},
// 				{0x00, 0x02, 0x03, 0x04},
// 			},
// 		},
// 	}

// 	for _, tc := range testCases {
// 		for _, vector := range tc.inputVectors {
// 			f.Add(bitstring.Pack(vector))
// 		}
// 	}

// 	f.Fuzz(func(t *testing.T, vector []uint8) {
// 		outputVector, err := bitstring.Pack(vector)

// 		if err != nil {
// 			require.NoError(t, err, "Invalid input")
// 		}

// 		for i := 0; i < len(vector); i++ {
// 			output := outputVector.Get(uint(i))
// 			if vector[i] != output {
// 				require.Equal(t, vector[i], output)
// 			}
// 		}
// 	})
// }

// func FuzzUnpack(f *testing.F){
// 	inputVector := bitstring.PackedBits{
// 		0b01001000, 0b00101100,
// 		0b01101010, 0b00011110,
// 		0b01011001, 0b00111101,
// 		0b01111011, 0b00001111,
// 	}
// 	f.Add(inputVector)

// 	f.Fuzz(func(t *testing.T, vector bitstring.PackedBits) {
// 		outputVector := inputVector.Unpack()

// 		for i := 0; i < len(inputVector)*8; i++ {
//             input := inputVector.Get(uint(i))
// 			if input != inputVector.Get(uint(i)) {
// 				require.Equal(t, input, outputVector[i])
// 			}
//         }
// 	})
// }

// func FuzzString(f *testing.F){
// 	testCases := []struct {
// 		inputPackedBits bitstring.PackedBits
// 	}{
// 		{
// 			inputPackedBits: bitstring.PackedBits{},
// 		},
// 		{
// 			inputPackedBits: bitstring.PackedBits{0x00, 0x0F},
// 		},
// 		{
// 			inputPackedBits: bitstring.PackedBits{0x00, 0x00},
// 		},
// 		{
// 			inputPackedBits: bitstring.PackedBits{0xFF, 0xFF},
// 		},
// 	}
// 	for _, tc := range testCases {
//         f.Add(tc.inputPackedBits)
//     }

// 	f.Fuzz(func(t *testing.T, input bitstring.PackedBits) {
// 		original := input
// 		input.String()

// 		if input.BitLen() != (8 * len(original)){
// 			require.Equal(t, input.BitLen(), (8 * len(original)))
// 		}

// 	})
// }

// func FuzzSwap(f *testing.F){
// 	testCases := []struct {
// 		input          bitstring.PackedBits
// 		i, j           int
// 	}{
// 		{
// 			input:          bitstring.PackedBits{0xFF},
// 			i:              10,
// 			j:              1,
// 		},
// 		{
// 			input:          bitstring.PackedBits{0xFF},
// 			i:              10,
// 			j:              -1,
// 		},
// 		{
// 			input:          bitstring.PackedBits{0xFF, 0xFF},
// 			i:              1,
// 			j:              2,
// 		},
// 		{
// 			input:          bitstring.PackedBits{0x00, 0x00},
// 			i:              1,
// 			j:              2,
// 		},
// 		{
// 			input:          bitstring.PackedBits{0xAb, 0x00},
// 			i:              0,
// 			j:              0,
// 		},
// 	}

// 	for _, tc := range testCases {
//         f.Add(tc.input, tc.i, tc.j)
//     }

// 	f.Fuzz(func(t *testing.T, input bitstring.PackedBits, i int, j int){

// 	})
// }

// func FuzzGet(f *testing.F){
// 	testCases := []struct {
// 		input          bitstring.PackedBits
// 		index          uint
// 	}{
// 		{
// 			input:          bitstring.PackedBits{0x12, 0x13},
// 			index:          20,
// 		},
// 		{
// 			input:          bitstring.PackedBits{0x12},
// 			index:          0,
// 		},
// 		{
// 			input:          bitstring.PackedBits{0x12, 0x00, 0xFF},
// 			index:          7,
// 		},
// 		{
// 			input:          bitstring.PackedBits{},
// 			index:          7,
// 		},
// 	}
// 	for _, tc := range testCases {
//         f.Add(tc.input, tc.index)
//     }
// 	f.Fuzz(func(t *testing.T, input bitstring.PackedBits, index uint){
//         output := input.Get(index)
//         require.Equal(t, input.Get(index), output)
//     })
// }
// func FuzzRepeatBits(f *testing.F){
// 	inputVector := bitstring.PackedBits{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}
// 	inputRepetition := []int {0, 1, 2, 3, 4}
	
// 	for _, repetition := range inputRepetition {
// 		f.Add(inputVector, repetition)
// 	}

// 	f.Fuzz(func(t *testing.T, input bitstring.PackedBits, repetition int){
// 		outputVector := inputVector.Repeat(repetition)

// 		for i := 0; i < len(inputVector)*8; i++ {
// 			for j := 0; j < repetition; j++ {
// 				output := outputVector.Get(uint(i*repetition + j))
// 				input := inputVector.Get(uint(i))
// 				if input != output {
//                     require.Equal(t, input, output)
//                 }
// 			}
// 		}

// 	})
// }
// func FuzzBitLen(f *testing.F){
// 	testCases := []struct {
// 		input          bitstring.PackedBits
// 	}{
// 		{
// 			input:          bitstring.PackedBits{0x00},
// 		},
// 		{
// 			input:          bitstring.PackedBits{0xFF, 0x00},
// 		},
// 		{
// 			input:          bitstring.PackedBits{},
// 		},
// 	}
	
// 	for _, tc := range testCases {
//         f.Add(tc.input)
//     }

// 	f.Fuzz(func(t *testing.T, input bitstring.PackedBits){
// 		result := input.BitLen()
// 		require.Equal(t, 8*len(input), result)
// 	})
// }
// func FuzzParse(f *testing.F){
// 	testCases := []struct {
// 		vector         string

// 	}{
// 		// {
// 		// 	vector:         "1abcd01010",
// 		// },
// 		{
// 			vector:         "01010101",
// 		},
// 		{
// 			vector:         "1111000011110000",
// 		},
// 	}
// 	for _, tc := range testCases {
//         f.Add(tc.vector)
//     }

// 	f.Fuzz(func(t *testing.T, vector string) {
// 		result, err := bitstring.Parse(vector)

// 		if err != nil {
//             require.Error(t, err, "Invalid input")
//         } else {
// 			result.Unpack()
// 			for i := 0; i < len(vector); i++ {
// 				if result[i] != vector[i] {
// 					require.Equal(t, vector[i], result[i])
// 				}
// 			}
// 		}
// 	})
// }
