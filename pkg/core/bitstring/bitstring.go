package bitstring

import (
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

// SelectBit interprets the byte-vector `vector` as if it were a _bit_-vector with len(vector) * 8 bits.
// it extracts the `index`th such bit, interpreted in the little-endian way (i.e., both across bytes and within bytes).
func SelectBit(vector []byte, index int) byte {
	// the bitwise tricks index >> 3 == index // 8 and index & 0x07 == index % 8 are designed to avoid CPU division.
	return vector[index>>3] >> (index & 0x07) & 0x01
}

// XorBytesInPlace computes out[i] = in[0][i] XOR in[1][i] XOR ...
func XorBytesInPlace(out []byte, in ...[]byte) error {
	if n := copy(out, in[0]); n != len(out) {
		return errs.NewInvalidArgument("XORing slices of different length")
	}
	for idx := 1; idx < len(in); idx++ {
		if len(in[idx]) != len(out) {
			return errs.NewInvalidArgument("XORing slices of different length")
		}
		for i := 0; i < len(out); i++ {
			out[i] ^= in[idx][i]
		}
	}
	return nil
}

func ReverseBytes(inBytes []byte) []byte {
	outBytes := make([]byte, len(inBytes))

	for i, j := 0, len(inBytes)-1; j >= 0; i, j = i+1, j-1 {
		outBytes[i] = inBytes[j]
	}

	return outBytes
}

// XorBytes computes in[0][i] XOR in[1][i] XOR ... in a new slice.
func XorBytes(in ...[]byte) ([]byte, error) {
	out := make([]byte, len(in[0]))
	if err := XorBytesInPlace(out, in...); err != nil {
		return nil, errs.WrapFailed(err, "xoring bytes")
	}
	return out, nil
}

// TransposePackedBits transposes a 2D matrix of "packed" bits (represented in
// groups of 8 bits per bytes), yielding a new 2D matrix of "packed" bits. If we
// were to unpack the bits, inputMatrixBits[i][j] == outputMatrixBits[j][i].
func TransposePackedBits(inputMatrix [][]byte) [][]byte {
	// Read input sizes and allocate output
	nRowsInput := len(inputMatrix)
	if nRowsInput%8 != 0 {
		panic("input matrix must have a number of rows divisible by 8")
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
	return transposedMatrix
}

// ByteSubBE is a constant time algorithm for subtracting
// 1 from the array as if it were a big number.
// 0 is considered a wrap which resets to 0xFF.
func ByteSubBE(b []byte) {
	carry := uint16(0)
	for i := range b {
		t := uint16(b[i]) + uint16(0x00ff) + carry
		b[i] = byte(t & 0xff)
		carry = t >> 8
	}
}
