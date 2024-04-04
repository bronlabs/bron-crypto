package fuzz

import (
	"encoding/binary"
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
				output1 := bitstring.PackedBits(inputMatrix[i]).Select(j)
				if err != nil {
					t.Skip()
				}
				output2 := bitstring.PackedBits(transposedMatrix[j][:]).Select(i)
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
