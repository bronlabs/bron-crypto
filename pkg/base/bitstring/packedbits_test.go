package bitstring_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
)

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

func TestPackBits(t *testing.T) {
	t.Parallel()

	inputVector := []byte{0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0}
	outputVector := bitstring.Pack(inputVector)
	for i := 0; i < len(inputVector); i++ {
		output := outputVector.Select(i)
		require.Equal(t, inputVector[i], output)
	}
}
