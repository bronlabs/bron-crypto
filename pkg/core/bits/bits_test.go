package bits_test

import (
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/bits"
	"github.com/stretchr/testify/require"
)

func TestSelectBit(t *testing.T) {
	vector := []byte{0x00, 0x00, 0x00, 0x00}
	for i := 0; i < 32; i++ {
		vector[i>>3] = 0x01 << (i & 0x07)
		require.Equal(t, byte(0x01), bits.SelectBit(vector, i))
	}
}

func TestXorBytes(t *testing.T) {
	in := [][]byte{
		{0x00, 0x04, 0x8, 0x00},
		{0x01, 0x01, 0x01, 0x01},
		{0x02, 0x02, 0x02, 0x01},
	}
	out := []byte{0x00, 0x00, 0x00, 0x00}
	bits.XorBytes(out, in...)
	require.Equal(t, []byte{0x03, 0x07, 0x0B, 0x00}, out)
}

func TestXorBytesNew(t *testing.T) {
	in := [][]byte{
		{0x00, 0x04, 0x8, 0x00},
		{0x01, 0x01, 0x01, 0x01},
		{0x02, 0x02, 0x02, 0x01},
	}
	out := bits.XorBytesNew(in...)
	require.Equal(t, []byte{0x03, 0x07, 0x0B, 0x00}, out)
}

func TestIntToByteArray(t *testing.T) {
	for i := 0; i < 100; i++ {
		require.Equal(t, [4]byte{0x00, 0x00, 0x00, byte(i)}, bits.IntToByteArray(i))
	}
	for i := 256; i < 356; i++ {
		require.Equal(t, [4]byte{0x00, 0x00, 0x01, byte(i - 256)}, bits.IntToByteArray(i))
	}
	for i := 65536; i < 65636; i++ {
		require.Equal(t, [4]byte{0x00, 0x01, 0x00, byte(i - 65536)}, bits.IntToByteArray(i))
	}
	for i := 16777216; i < 16777316; i++ {
		require.Equal(t, [4]byte{0x01, 0x00, 0x00, byte(i - 16777216)}, bits.IntToByteArray(i))
	}
}

func TestBoolToByte(t *testing.T) {
	require.Equal(t, byte(0x00), bits.BoolToByte(false))
	require.Equal(t, byte(0x01), bits.BoolToByte(true))
}
