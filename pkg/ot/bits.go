package ot

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

// PackedBits is a byte vector of little-endian packed bits.
type PackedBits []byte

// Pack compresses the bits in the input vector v, truncating each input byte to
// its least significant bit. E.g., [0x01,0x01,0x01,0x01, 0x00,0x00,0x01,0x00] ---> [0xF0].
func Pack(unpackedBits []uint8) (PackedBits, error) {
	vOut := PackedBits(make([]byte, (len(unpackedBits)+7)/8))
	isNonBinary := uint8(0)

	for i, bit := range unpackedBits {
		isNonBinary |= bit
		vOut[i/8] |= (bit & 0b1) << (i % 8)
	}
	if isNonBinary&0xFE != 0x00 {
		return nil, errs.NewArgument("Input vector contains non-binary elements")
	}

	return vOut, nil
}

// Unpack expands the bits of the input vector into separate bytes.
// E.g., [0xF0,0x12] ---> [1,1,1,1, 0,0,0,0, 0,0,0,1, 0,0,1,0].
func (pb PackedBits) Unpack() []uint8 {
	vOut := make([]byte, pb.BitLen())
	for i := range pb.BitLen() {
		vOut[i] = pb.Get(uint(i))
	}
	return vOut
}

// String returns a string representation of the packed bits.
func (pb PackedBits) String() string {
	return fmt.Sprintf("%v", pb.Unpack())
}

// Get gets the `i`th bit of a packed bits vector.
// E.g., [0x12, 0x34] --> [0,1,0,0, 1,0,0,0, 1,1,0,0, 0,0,1,0].
func (pb PackedBits) Get(i uint) uint8 {
	return (pb[i/8] >> (i % 8)) & 0b1
}

// Swap swaps the `i`th and `j`th bits.
func (pb PackedBits) Swap(i, j uint) {
	iBit := (pb[i/8] >> (i % 8)) & 0b1
	jBit := (pb[j/8] >> (j % 8)) & 0b1

	pb[i/8] &^= 1 << (i % 8)
	pb[i/8] |= jBit << (i % 8)

	pb[j/8] &^= 1 << (j % 8)
	pb[j/8] |= iBit << (j % 8)
}

// Set sets the `i`th bit of a packed bits vector. Input `bit` is truncated
// to its least significant bit (i.e., we only consider the last bit of `bit`).
func (pb PackedBits) Set(i uint) {
	pb[i/8] |= 1 << (i % 8)
}

// Clear sets the `i`th bit of a packed bits vector to 0.
func (pb PackedBits) Clear(i uint) {
	pb[i/8] &^= 1 << (i % 8)
}

// Repeat repeats the bits in the input vector `nrepetitions` times. E.g.,
// if v = [0,1,0,1] and nrepetitions = 2, then the output is [0,0,1,1,0,0,1,1].
// To do so, bits must be unpacked, repeated, and packed in the output.
func (pb PackedBits) Repeat(nRepetitions int) PackedBits {
	vOut := PackedBits(make([]byte, len(pb)*nRepetitions))
	nextBit := 0
	for i := range pb.BitLen() {
		bit := pb.Get(uint(i))
		for range nRepetitions {
			vOut[nextBit/8] |= bit << (nextBit % 8)
			nextBit++
		}
	}
	return vOut
}

func (pb PackedBits) BitLen() int {
	return len(pb) * 8
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
	for i := range nRowsInput {
		if len(inputMatrix[i]) != len(inputMatrix[0]) {
			return nil, errs.NewArgument("input matrix must be a 2D matrix")
		}
	}

	nColsInputBytes := len(inputMatrix[0])
	nRowsOutput := nColsInputBytes << 3
	nColsOutputBytes := nRowsInput >> 3
	transposedMatrix := make([][]byte, nRowsOutput)
	for i := range nRowsOutput {
		transposedMatrix[i] = make([]byte, nColsOutputBytes)
	}
	// transpose the matrix bits, one bit at a time
	for rowByte := range nColsOutputBytes {
		for rowBitWithinByte := range 8 {
			for columnByte := range nColsInputBytes {
				for columnBitWithinByte := range 8 {
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

func Parse(v string) (PackedBits, error) {
	if v == "" {
		return nil, errs.NewArgument("Input string cannot be empty")
	}

	byteLen := (len(v) + 7) / 8
	packedBits := make(PackedBits, byteLen)

	for i, char := range v {
		if char != '0' && char != '1' {
			return nil, errs.NewArgument("Invalid character in the input")
		}
		byteIndex := i / 8
		bitPos := uint(i % 8)

		if char == '1' {
			packedBits[byteIndex] |= 1 << (byte(bitPos))
		}
	}

	return packedBits, nil
}
