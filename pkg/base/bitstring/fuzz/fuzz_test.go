package fuzz

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf8"
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
	testCases := []struct {
		input int32
	}{
		{123456789},
		{-123456789},
		{0},
	}

	for _,tc := range testCases {
		f.Add(tc.input)
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

	testCases := []struct{
		inBytes []byte
		padLagth int
	}{
		{[]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, 4},
		{[]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, 0},
		{[]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, -4},
	}

	for _, tc := range testCases {
		f.Add(tc.inBytes, tc.padLagth)
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

	testCases := []struct{
		inBytes []byte
		padLagth int
	}{
		{[]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, 4},
		{[]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, 0},
		{[]byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}, -4},
	}

	for _, tc := range testCases {
		f.Add(tc.inBytes, tc.padLagth)
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
	maxLength := 10

	testCases := []struct{
		inputText string
	}{
		{
			inputText: "Hello",
		},
		{
			inputText: "HelloWorld",
		},
		{
			inputText: "Hello, World!",
		},
	}

	for _, tc := range testCases {
        f.Add(tc.inputText, maxLength)
    }

	f.Fuzz(func(t *testing.T, input string, maxLength int){
		result := bitstring.TruncateWithEllipsis(input, maxLength)

		if maxLength <= 0 {
			require.Equal(t, input, result)
		}
		if utf8.RuneCountInString(input) <= maxLength {
			require.Equal(t, input, result)
		} else {
			require.LessOrEqual(t, utf8.RuneCountInString(result), maxLength, "Result exceeds max length")

			require.Equal(t, "...", []rune(result)[utf8.RuneCountInString(result)-1], "result string should end with ellipsis")
		}
	})
}