package bitstring

import (
	"fmt"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

// PackedBits is a byte vector of little-endian packed bits.
type PackedBits []byte

// Pack compresses the bits in the input vector v, truncating each input byte to
// its least significant bit. E.g., [0x01,0x01,0x01,0x01, 0x00,0x00,0x01,0x00] ---> [0xF0].
func Pack(unpackedBits []uint8) PackedBits {
	vOut := PackedBits(make([]byte, (len(unpackedBits)+7)/8))
	for i, bit := range unpackedBits {
		vOut[i/8] |= (bit & 0b1) << (i % 8)
	}
	return vOut
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
	// index & 0x07 == index % 8 are designed to avoid CPU division.
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
			packedBits[byteIndex] |= 1 << (7 - bitPos)
		}
	}

	return packedBits, nil
}
