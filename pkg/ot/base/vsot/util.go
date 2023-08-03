package vsot

import "github.com/copperexchange/crypto-primitives-go/pkg/core/bits"

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
	receiver.Output.RandomChoiceBits = make([]int, receiver.BatchSize)
	for i := 0; i < len(receiver.Output.RandomChoiceBits); i++ {
		receiver.Output.RandomChoiceBits[i] = int(bits.SelectBit(receiver.Output.PackedRandomChoiceBits, i))
	}
}
