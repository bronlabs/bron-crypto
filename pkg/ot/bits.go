package ot

import (
	"encoding/binary"
	"fmt"
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
		return nil, ErrInvalidArgument.WithMessage("input vector contains non-binary elements")
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

// BitLen returns the number of bits represented by the packed slice.
func (pb PackedBits) BitLen() int {
	return len(pb) * 8
}

// Parse converts a binary string into PackedBits.
func Parse(v string) (PackedBits, error) {
	if v == "" {
		return nil, ErrInvalidArgument.WithMessage("input string cannot be empty")
	}

	byteLen := (len(v) + 7) / 8
	packedBits := make(PackedBits, byteLen)

	for i, char := range v {
		if char != '0' && char != '1' {
			return nil, ErrInvalidArgument.WithMessage("invalid character in the input")
		}
		byteIndex := i / 8
		bitPos := uint(i % 8)

		if char == '1' {
			packedBits[byteIndex] |= 1 << (byte(bitPos))
		}
	}

	return packedBits, nil
}

// TransposePackedBits transposes a 2D matrix of "packed" bits (represented in
// groups of 8 bits per bytes), yielding a new 2D matrix of "packed" bits. If we
// were to unpack the bits, inputMatrixBits[i][j] == outputMatrixBits[j][i].
func TransposePackedBits(inputMatrix [][]byte) ([][]byte, error) {
	if len(inputMatrix)%64 != 0 {
		return transposePackedBitsSlow(inputMatrix)
	}
	for _, c := range inputMatrix {
		if len(c)%8 != 0 {
			return transposePackedBitsSlow(inputMatrix)
		}
	}

	return transposePackedBitsFast(inputMatrix)
}

// transposePackedBitsSlow transposes a 2D matrix of "packed" bits (represented in
// groups of 8 bits per bytes), yielding a new 2D matrix of "packed" bits. If we
// were to unpack the bits, inputMatrixBits[i][j] == outputMatrixBits[j][i].
func transposePackedBitsSlow(inputMatrix [][]byte) ([][]byte, error) {
	// Read input sizes and allocate output
	nRowsInput := len(inputMatrix)
	if nRowsInput%8 != 0 || nRowsInput == 0 {
		return nil, ErrInvalidArgument.WithMessage("input matrix must have a number of rows divisible by 8")
	}
	// check if array is a matrix
	for i := range nRowsInput {
		if len(inputMatrix[i]) != len(inputMatrix[0]) {
			return nil, ErrInvalidArgument.WithMessage("input matrix must be a 2D matrix")
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

// transposePackedBitsFast transposes a packed bit matrix using 64x64 block transposes.
// The number of rows and columns (in bits) must be multiples of 64.
func transposePackedBitsFast(inputMatrix [][]byte) ([][]byte, error) {
	nRowsInput := len(inputMatrix)
	if nRowsInput == 0 || nRowsInput%64 != 0 {
		return nil, ErrInvalidArgument.WithMessage("input matrix must have a number of rows divisible by 64")
	}
	if len(inputMatrix[0]) == 0 || len(inputMatrix)%8 != 0 {
		return nil, ErrInvalidArgument.WithMessage("input matrix must have at least one column")
	}
	for i := range nRowsInput {
		if len(inputMatrix[i]) != len(inputMatrix[0]) {
			return nil, ErrInvalidArgument.WithMessage("input matrix must be a 2D matrix")
		}
	}

	nColsInputBytes := len(inputMatrix[0])
	nColsInputBits := nColsInputBytes * 8
	nRowsOutput := nColsInputBits
	nColsOutputBytes := nRowsInput / 8
	transposedMatrix := make([][]byte, nRowsOutput)
	for i := range nRowsOutput {
		transposedMatrix[i] = make([]byte, nColsOutputBytes)
	}

	for rowBlock := 0; rowBlock < nRowsInput; rowBlock += 64 {
		for colBlock := 0; colBlock < nColsInputBits; colBlock += 64 {
			var block [64]uint64
			colByte := colBlock / 8
			for i := range 64 {
				block[i] = binary.LittleEndian.Uint64(inputMatrix[rowBlock+i][colByte : colByte+8])
			}
			transpose64(block[:])
			rowByte := rowBlock / 8
			for i := range 64 {
				binary.LittleEndian.PutUint64(transposedMatrix[colBlock+i][rowByte:rowByte+8], block[i])
			}
		}
	}

	return transposedMatrix, nil
}

func transpose64(block []uint64) {
	masks := [6]uint64{
		0x5555555555555555,
		0x3333333333333333,
		0x0f0f0f0f0f0f0f0f,
		0x00ff00ff00ff00ff,
		0x0000ffff0000ffff,
		0x00000000ffffffff,
	}

	for stage := range 6 {
		step := 1 << stage
		mask := masks[stage]
		shift := uint(step)
		for base := 0; base < 64; base += 2 * step {
			for i := range step {
				a := block[base+i]
				b := block[base+i+step]
				block[base+i] = (a & mask) | ((b & mask) << shift)
				block[base+i+step] = ((a >> shift) & mask) | (b & ^mask)
			}
		}
	}
}
