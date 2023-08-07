package bitstring_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
)

func TestSelectBit(t *testing.T) {
	vector := []byte{0x00, 0x00, 0x00, 0x00}
	for i := 0; i < 32; i++ {
		vector[i>>3] = 0x01 << (i & 0x07)
		require.Equal(t, byte(0x01), bitstring.SelectBit(vector, i))
	}
}

func TestXorBytes(t *testing.T) {
	in := [][]byte{
		{0x00, 0x04, 0x8, 0x00},
		{0x01, 0x01, 0x01, 0x01},
		{0x02, 0x02, 0x02, 0x01},
	}
	out := []byte{0x00, 0x00, 0x00, 0x00}
	err := bitstring.XorBytesInPlace(out, in...)
	require.NoError(t, err)
	require.Equal(t, []byte{0x03, 0x07, 0x0B, 0x00}, out)
}

func TestXorBytesNew(t *testing.T) {
	in := [][]byte{
		{0x00, 0x04, 0x8, 0x00},
		{0x01, 0x01, 0x01, 0x01},
		{0x02, 0x02, 0x02, 0x01},
	}
	out, err := bitstring.XorBytes(in...)
	require.NoError(t, err)
	require.Equal(t, []byte{0x03, 0x07, 0x0B, 0x00}, out)
}

func TestIntToByteArrayBE(t *testing.T) {
	// int8
	for i := int8(0); i < 100; i++ {
		require.Equal(t, []byte{byte(i)}, bitstring.ToByteArrayBE(i))
	}
	// uint16
	for i := uint16(0); i < 100; i++ {
		require.Equal(t, []byte{0x00, byte(i)}, bitstring.ToByteArrayBE(i))
	}
	for i := uint16(256); i < 356; i++ {
		require.Equal(t, []byte{0x01, byte(i - 256)}, bitstring.ToByteArrayBE(i))
	}
	// int32
	for i := int32(0); i < 100; i++ {
		require.Equal(t, []byte{0x00, 0x00, 0x00, byte(i)}, bitstring.ToByteArrayBE(i))
	}
	for i := int32(65536); i < 65636; i++ {
		require.Equal(t, []byte{0x00, 0x01, 0x00, byte(i - 65536)}, bitstring.ToByteArrayBE(i))
	}
	for i := int32(16777216); i < 16777316; i++ {
		require.Equal(t, []byte{0x01, 0x00, 0x00, byte(i - 16777216)}, bitstring.ToByteArrayBE(i))
	}
	// uint64
	for i := uint64(0); i < 100; i++ {
		require.Equal(t, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, byte(i)}, bitstring.ToByteArrayBE(i))
	}
	for i := uint64(4294967296); i < 4294967396; i++ {
		require.Equal(t, []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, byte(i - 4294967296)}, bitstring.ToByteArrayBE(i))
	}
	for i := uint64(281474976710656); i < 281474976710756; i++ {
		require.Equal(t, []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, byte(i - 281474976710656)}, bitstring.ToByteArrayBE(i))
	}

}

func TestIntToByteArrayLE(t *testing.T) {
	// int8
	for i := int8(0); i < 100; i++ {
		require.Equal(t, []byte{byte(i)}, bitstring.ToByteArrayLE(i))
	}
	// uint16
	for i := uint16(0); i < 100; i++ {
		require.Equal(t, []byte{byte(i), 0x00}, bitstring.ToByteArrayLE(i))
	}
	for i := uint16(256); i < 356; i++ {
		require.Equal(t, []byte{byte(i - 256), 0x01}, bitstring.ToByteArrayLE(i))
	}
	// int32
	for i := int32(0); i < 100; i++ {
		require.Equal(t, []byte{byte(i), 0x00, 0x00, 0x00}, bitstring.ToByteArrayLE(i))
	}
	for i := int32(65536); i < 65636; i++ {
		require.Equal(t, []byte{byte(i - 65536), 0x00, 0x01, 0x00}, bitstring.ToByteArrayLE(i))
	}
	for i := int32(16777216); i < 16777316; i++ {
		require.Equal(t, []byte{byte(i - 16777216), 0x00, 0x00, 0x01}, bitstring.ToByteArrayLE(i))
	}
	// uint64
	for i := uint64(0); i < 100; i++ {
		require.Equal(t, []byte{byte(i), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, bitstring.ToByteArrayLE(i))
	}
	for i := uint64(4294967296); i < 4294967396; i++ {
		require.Equal(t, []byte{byte(i - 4294967296), 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, bitstring.ToByteArrayLE(i))
	}
	for i := uint64(281474976710656); i < 281474976710756; i++ {
		require.Equal(t, []byte{byte(i - 281474976710656), 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}, bitstring.ToByteArrayLE(i))
	}
}

func TestBoolTo(t *testing.T) {
	require.Equal(t, byte(0x00), bitstring.BoolTo[byte](false))
	require.Equal(t, byte(0x01), bitstring.BoolTo[byte](true))
	require.Equal(t, uint(0x00), bitstring.BoolTo[uint](false))
	require.Equal(t, uint(0x01), bitstring.BoolTo[uint](true))
	require.Equal(t, int(0x00), bitstring.BoolTo[int](false))
	require.Equal(t, int(0x01), bitstring.BoolTo[int](true))
}

func TestTransposeBooleanMatrix(t *testing.T) {
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
	transposedMatrix := bitstring.TransposePackedBits(inputMatrix)
	for i := 0; i < len(inputMatrix); i++ {
		for j := 0; j < len(transposedMatrix); j++ {
			// Check that the bit at position i in the jth row of the input matrix.
			// is equal to the bit at position j in the ith row of the transposed matrix.
			// using bitstring.SelectBit (careful! it takes a byte array as input)
			require.Equal(t,
				bitstring.SelectBit(inputMatrix[i], j),
				bitstring.SelectBit(transposedMatrix[j][:], i))
		}
	}
}
