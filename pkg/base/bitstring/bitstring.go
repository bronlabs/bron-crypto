package bitstring

import (
	"encoding/binary"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

// SelectBit interprets the byte-vector `vector` as if it were a _bit_-vector with len(vector) * 8 bits.
// it extracts the `index`th such bit, interpreted in the little-endian way (i.e., both across bytes and within bytes).
func SelectBit(vector []byte, index int) (byte, error) {
	if index < 0 || index >= binary.Size(vector)*8 {
		return 0, errs.NewInvalidArgument("index out of bounds")
	}
	// the bitwise tricks index >> 3 == index // 8 and index & 0x07 == index % 8 are designed to avoid CPU division.
	return vector[index>>3] >> (index & 0x07) & 0x01, nil
}

// ReverseBytes reverses the order of the bytes in a new slice.
func ReverseBytes(inBytes []byte) []byte {
	outBytes := make([]byte, len(inBytes))

	for i, j := 0, len(inBytes)-1; j >= 0; i, j = i+1, j-1 {
		outBytes[i] = inBytes[j]
	}

	return outBytes
}

// ReverseAndPadBytes reverses the order of the bytes in a new slice.
func ReverseAndPadBytes(inBytes []byte, padLen int) []byte {
	outBytes := make([]byte, len(inBytes)+padLen)

	for i, j := 0, len(inBytes)-1; j >= 0; i, j = i+1, j-1 {
		outBytes[i] = inBytes[j]
	}

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
	if nRowsInput%8 != 0 {
		return nil, errs.NewInvalidArgument("input matrix must have a number of rows divisible by 8")
	}
	// check if array is a matrix
	for i := 0; i < nRowsInput; i++ {
		if len(inputMatrix[i]) != len(inputMatrix[0]) {
			return nil, errs.NewInvalidArgument("input matrix must be a matrix")
		}
	}

	nColsInputBytes := len(inputMatrix[0])
	nRowsOutput := nColsInputBytes << 3
	nColsOutputBytes := nRowsInput >> 3
	transposedMatrix := make([][]byte, nRowsOutput)
	for i := 0; i < nRowsOutput; i++ {
		transposedMatrix[i] = make([]byte, nColsOutputBytes)
	}
	// Actually transpose the matrix bits
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
