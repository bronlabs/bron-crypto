package ot

import "unsafe"

// Choices packs the receiver's choice bits of a batch of L OTs into L/8
// elements: the choice bit of OT i is bit i%8 of element i/8, least-significant
// bit first.
type Choices []byte

// BitLen returns the number of choice bits L.
func (c Choices) BitLen() int {
	return len(c) * 8
}

// Message is the type set of OT messages: fixed-width byte arrays, so that the
// message length K is a property of the type and every message of a batch has
// it by construction.
type Message interface {
	~[16]byte | ~[32]byte
}

type (
	// Message128 is a 128-bit OT message.
	Message128 [16]byte
	// Message256 is a 256-bit OT message.
	Message256 [32]byte
)

// MessageBitLen returns the message length K of M in bits.
func MessageBitLen[M Message]() int {
	var m M
	return len(m) * 8
}

// MessageAsSlice returns a view of the message's storage. The slice aliases
// the array: writes through it change the message, and it must not outlive it.
func MessageAsSlice[M Message](m *M) []byte {
	return unsafe.Slice(&(*m)[0], len(*m))
}

// messageFromBytes copies b into a message of type M, rejecting any other
// width. It is the width check of the deserialisation boundary: the CBOR
// decoder pads or truncates byte strings into fixed-size arrays silently, so
// wire data is decoded into slices and converted here.
func messageFromBytes[M Message](b []byte) (M, error) {
	var m M
	if len(b) != len(m) {
		return m, ErrInvalidArgument.WithMessage("message holds %d bits, expected %d", len(b)*8, len(m)*8)
	}
	copy(MessageAsSlice(&m), b)
	return m, nil
}
