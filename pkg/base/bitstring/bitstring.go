package bitstring

import (
	"encoding/binary"
	"fmt"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

// SelectBit gets the `i`th bit of a byte vector `v` interpreted as little-endian packed bits.
// E.g., [0x12, 0x34] --> [0,1,0,0, 1,0,0,0, 1,1,0,0, 0,0,1,0].
func SelectBit(v []byte, i int) byte {
	// index & 0x07 == index % 8 are designed to avoid CPU division.
	return v[i/8] >> (i & 0x07) & 0x01
}

// ReverseBytes reverses the order of the bytes in a new slice.
func ReverseBytes(inBytes []byte) []byte {
	outBytes := make([]byte, len(inBytes))

	for i, j := 0, len(inBytes)-1; j >= 0; i, j = i+1, j-1 {
		outBytes[i] = inBytes[j]
	}

	return outBytes
}

// PadToLeft pads the input bytes to the left with padLen zeroed bytes.
func PadToLeft(inBytes []byte, padLen int) []byte {
	if padLen < 0 {
		return inBytes
	}
	outBytes := make([]byte, padLen+len(inBytes))
	copy(outBytes[padLen:], inBytes)
	return outBytes
}

// PadToRight pads the input bytes to the right with padLen zeroed bytes.
func PadToRight(inBytes []byte, padLen int) []byte {
	if padLen < 0 {
		return inBytes
	}
	outBytes := make([]byte, len(inBytes)+padLen)
	copy(outBytes[:len(outBytes)-padLen], inBytes)
	return outBytes
}

// Memset sets all the bytes in the slice to the given value.
func Memset(buffer []byte, value byte) {
	for i := range buffer {
		buffer[i] = value
	}
}

// TransposePackedBits transposes a 2D matrix of "packed" bits (represented in
// groups of 8 bits per bytes), yielding a new 2D matrix of "packed" bits. If we
// were to unpack the bits, inputMatrixBits[i][j] == outputMatrixBits[j][i].
func TransposePackedBits(inputMatrix [][]byte) ([][]byte, error) {
	// Read input sizes and allocate output
	nRowsInput := len(inputMatrix)
	if nRowsInput%8 != 0 || nRowsInput == 0 {
		return nil, errs.NewArgument("input matrix must have a number of rows divisible by 8")
	}
	// check if array is a matrix
	for i := 0; i < nRowsInput; i++ {
		if len(inputMatrix[i]) != len(inputMatrix[0]) {
			return nil, errs.NewArgument("input matrix must be a 2D matrix")
		}
	}

	nColsInputBytes := len(inputMatrix[0])
	nRowsOutput := nColsInputBytes << 3
	nColsOutputBytes := nRowsInput >> 3
	transposedMatrix := make([][]byte, nRowsOutput)
	for i := 0; i < nRowsOutput; i++ {
		transposedMatrix[i] = make([]byte, nColsOutputBytes)
	}
	// transpose the matrix bits, one bit at a time
	for rowByte := 0; rowByte < nColsOutputBytes; rowByte++ {
		for rowBitWithinByte := 0; rowBitWithinByte < 8; rowBitWithinByte++ {
			for columnByte := 0; columnByte < nColsInputBytes; columnByte++ {
				for columnBitWithinByte := 0; columnBitWithinByte < 8; columnBitWithinByte++ {
					rowBit := rowByte<<3 + rowBitWithinByte
					columnBit := columnByte<<3 + columnBitWithinByte
					// Grab the corresponding  bit at input[rowBit][columnBit]
					bitAtInputRowBitColumnBit := inputMatrix[rowBit][columnByte] >> columnBitWithinByte & 0x01
					// Place the bit at output[columnBit][rowBit]
					shiftedBit := bitAtInputRowBitColumnBit << rowBitWithinByte
					transposedMatrix[columnBit][rowByte] |= shiftedBit
				}
			}
		}
	}
	return transposedMatrix, nil
}

// ByteSubLE is a constant time algorithm for subtracting
// 1 from the array as if it were a big number.
// 0 is considered a wrap which resets to 0xFF.
func ByteSubLE(b []byte) {
	carry := uint16(0)
	for i := range b {
		t := uint16(b[i]) + uint16(0x00ff) + carry
		b[i] = byte(t & 0xff)
		carry = t >> 8
	}
}

func ToBytesLE(i int) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(i))
	return b
}

// RepeatBits repeats the bits in the input vector v `nrepetitions` times. E.g.,
// if v = [0,1,0,1] and nrepetitions = 2, then the output is [0,0,1,1,0,0,1,1].
// To do so, bits must be unpacked, repeated, and packed in the output.
func RepeatBits(v []byte, nrepetitions int) []byte {
	vOut := make([]byte, len(v)*nrepetitions)
	nextBit := 0
	for i := 0; i < len(v)*8; i++ {
		bit := v[i/8] >> (i & 0x07) & 0x01
		for j := 0; j < nrepetitions; j++ {
			vOut[nextBit/8] |= bit << (nextBit & 0x07)
			nextBit++
		}
	}
	return vOut
}

// UnpackBits unpacks the bits in the input vector v.
// E.g., [0xF0,0x12] ---> [1,1,1,1, 0,0,0,0, 0,0,0,1, 0,0,1,0].
func UnpackBits(v []byte) []byte {
	vOut := make([]byte, len(v)*8)
	for i := 0; i < len(v)*8; i++ {
		vOut[i] = v[i/8] >> (i & 0x07) & 0x01
	}
	return vOut
}

// PackBits packs the bits in the input vector v. Treats every non-zero input byte as 1.
// E.g., [1,1,1,1, 0,0,0,0, 0,0,0,1, 0,0,1,0] ---> [0xF0,0x12].
func PackBits(v []byte) []byte {
	vOut := make([]byte, (len(v)+7)/8)
	for i := 0; i < len(v); i++ {
		bit := byte(0)
		if v[i] != 0 {
			bit = 1
		}
		vOut[i/8] |= bit << (i & 0x07)
	}
	return vOut
}

func TruncateWithEllipsis(text string, maxLen int) string {
	if len(text) > maxLen {
		return text[:maxLen] + fmt.Sprintf("...(%d)", len(text)-maxLen)
	}
	return text
}
