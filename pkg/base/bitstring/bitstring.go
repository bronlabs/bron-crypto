package bitstring

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/exp/constraints"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

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

func ToBytesLE(i int) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(i))
	return b
}

func TruncateWithEllipsis(text string, maxLen int) string {
	if len(text) > maxLen {
		return text[:maxLen] + fmt.Sprintf("...(%d)", len(text)-maxLen)
	}
	return text
}

// Memclr clears a byte slice. Compiles to `memclr` (https://github.com/golang/go/issues/5373).
func Memclr[T constraints.Integer](dst []T) {
	for i := range dst {
		dst[i] = 0
	}
}
