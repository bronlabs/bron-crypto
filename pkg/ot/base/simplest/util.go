package simplest

// xorBytes computes c = a xor b.
func xorBytes(a, b [DigestSize]byte) (c [DigestSize]byte) {
	for i := 0; i < DigestSize; i++ {
		c[i] = a[i] ^ b[i]
	}
	return
}

// initChoice initializes the receiver's choice array from the PackedRandomChoiceBits array
func (receiver *Receiver) initChoice() {
	// unpack the random values in PackedRandomChoiceBits into bits in Choice
	receiver.Output.RandomChoiceBits = make([]int, receiver.batchSize)
	for i := 0; i < len(receiver.Output.RandomChoiceBits); i++ {
		receiver.Output.RandomChoiceBits[i] = int(ExtractBitFromByteVector(receiver.Output.PackedRandomChoiceBits, i))
	}
}

// ExtractBitFromByteVector interprets the byte-vector `vector` as if it were a _bit_-vector with len(vector) * 8 bits.
// it extracts the `index`th such bit, interpreted in the little-endian way (i.e., both across bytes and within bytes).
func ExtractBitFromByteVector(vector []byte, index int) byte {
	// the bitwise tricks index >> 3 == index // 8 and index & 0x07 == index % 8 are designed to avoid CPU division.
	return vector[index>>3] >> (index & 0x07) & 0x01
}
