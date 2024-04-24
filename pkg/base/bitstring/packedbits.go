package bitstring

import "fmt"

// PackedBits is a byte vector of little-endian packed bits.
type PackedBits []byte

// Pack compresses the bits in the input vector v, truncating each input byte to
// its least significant bit. E.g., [0x01,0x01,0x01,0x01, 0x00,0x00,0x01,0x00] ---> [0xF0].
func Pack(v []byte) PackedBits {
	vOut := PackedBits(make([]byte, (len(v)+7)/8))
	for i := range v {
		vOut.Set(i, v[i])
	}
	return vOut
}

// Unpack expandsthe bits of the input vector into separate bytes.
// E.g., [0xF0,0x12] ---> [1,1,1,1, 0,0,0,0, 0,0,0,1, 0,0,1,0].
func (pb PackedBits) Unpack() []byte {
	vOut := make([]byte, pb.BitLen())
	for i := range pb.BitLen() {
		vOut[i] = pb.Select(i)
	}
	return vOut
}

// String returns a string representation of the packed bits.
func (pb PackedBits) String() string {
	return fmt.Sprintf("%v", pb.Unpack())
}

// Select gets the `i`th bit of a packed bits vector.
// E.g., [0x12, 0x34] --> [0,1,0,0, 1,0,0,0, 1,1,0,0, 0,0,1,0].
func (pb PackedBits) Select(i int) byte {
	// index & 0x07 == index % 8 are designed to avoid CPU division.
	return pb[i/8] >> (i & 0x07) & 0x01
}

// Swap swaps the `i`th and `j`th bits.
func (pb PackedBits) Swap(i, j int) {
	ibit := pb.Select(i)
	jbit := pb.Select(j)
	pb.Set(i, jbit)
	pb.Set(j, ibit)
}

// Set sets the `i`th bit of a packed bits vector. Input `bit` is truncated
// to its least significant bit (i.e., we only consider the last bit of `bit`).
func (pb PackedBits) Set(i int, bit byte) {
	// index & 0x07 == index % 8 are designed to avoid CPU division.
	pb[i/8] |= (bit & 0x01) << (i & 0x07)
}

// Unset sets the `i`th bit of a packed bits vector to 0.
func (pb PackedBits) Unset(i int) {
	pb.Set(i, 0)
}

// Repeat repeats the bits in the input vector `nrepetitions` times. E.g.,
// if v = [0,1,0,1] and nrepetitions = 2, then the output is [0,0,1,1,0,0,1,1].
// To do so, bits must be unpacked, repeated, and packed in the output.
func (pb PackedBits) Repeat(nrepetitions int) PackedBits {
	vOut := PackedBits(make([]byte, len(pb)*nrepetitions))
	nextBit := 0
	for i := range pb.BitLen() {
		bit := pb.Select(i)
		for range nrepetitions {
			vOut.Set(nextBit, bit)
			nextBit++
		}
	}
	return vOut
}

func (pb PackedBits) BitLen() int {
	return len(pb) * 8
}