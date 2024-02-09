package utils

import (
	"encoding/binary"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type bits struct{}

var Bits bits

// Select gets the `i`th bit of a byte vector interpreted as little-endian packed bits.
// E.g., [0x12, 0x34] --> [0,1,0,0, 1,0,0,0, 1,1,0,0, 0,0,1,0].
func (bits) Select(v []byte, i int) (byte, error) {
	if i < 0 || i >= binary.Size(v)*8 {
		return 0, errs.NewInvalidArgument("index out of bounds")
	}
	// the bitwise tricks index >> 3 == index // 8 and index & 0x07 == index % 8 are designed to avoid CPU division.
	return v[i/8] >> (i & 0x07) & 0x01, nil
}

// TransposePacked transposes a 2D matrix of "packed" bits (represented in
// groups of 8 bits per bytes), yielding a new 2D matrix of "packed" bits. If we
// were to unpack the bits, inputMatrixBits[i][j] == outputMatrixBits[j][i].
func (bits) TransposePacked(inputMatrix [][]byte) ([][]byte, error) {
	// Read input sizes and allocate output
	nRowsInput := len(inputMatrix)
	if nRowsInput%8 != 0 || nRowsInput == 0 {
		return nil, errs.NewInvalidArgument("input matrix must have a number of rows divisible by 8")
	}
	// check if array is a matrix
	for i := 0; i < nRowsInput; i++ {
		if len(inputMatrix[i]) != len(inputMatrix[0]) {
			return nil, errs.NewInvalidArgument("input matrix must be a 2D matrix")
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

// Repeat repeats the bits in the input vector v `repetitions` times. E.g.,
// if v = [0,1,0,1] and repetitions = 2, then the output is [0,0,1,1,0,0,1,1].
// To do so, bits must be unpacked, repeated, and packed in the output.
func (bits) Repeat(v []byte, repetitions int) []byte {
	vOut := make([]byte, len(v)*repetitions)
	nextBit := 0
	for i := 0; i < len(v)*8; i++ {
		bit := v[i/8] >> (i & 0x07) & 0x01
		for j := 0; j < repetitions; j++ {
			vOut[nextBit/8] |= bit << (nextBit & 0x07)
			nextBit++
		}
	}
	return vOut
}

// Unpack unpacks the bits in the input vector v.
// E.g., [0xF0,0x12] ---> [1,1,1,1, 0,0,0,0, 0,0,0,1, 0,0,1,0].
func (bits) Unpack(v []byte) []byte {
	vOut := make([]byte, len(v)*8)
	for i := 0; i < len(v)*8; i++ {
		vOut[i] = v[i/8] >> (i & 0x07) & 0x01
	}
	return vOut
}

// Pack packs the bits in the input vector v. Treats every non-zero input byte as 1.
// E.g., [1,1,1,1, 0,0,0,0, 0,0,0,1, 0,0,1,0] ---> [0xF0,0x12].
func (bits) Pack(v []byte) []byte {
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
