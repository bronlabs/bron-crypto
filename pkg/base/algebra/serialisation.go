package algebra

import "github.com/cronokirby/saferith"

type NatSerialization[E Element] interface {
	// Uint64 casts the scalar down to a 64-bit integer. Might overflow.
	Uint64() uint64
	// SetNat returns a new element set to the value of `v mod S.Order()`.
	SetNat(v *saferith.Nat) E
	// Nat casts this element as a Nat.
	Nat() *saferith.Nat
}

type IntSerialization[E Element] interface {
	Int() Int
	FromInt(v Int) E
}

type BytesSerialization[E Element] interface {
	// Bytes returns the canonical big-endian byte representation of this element.
	// s.t. this = Σ_{i=0}^{k-1} (this.Bytes()[i] << 8*(k-i-1) ). The result
	// is always FieldBytes long.
	Bytes() []byte
	// SetBytes creates an element from a big-endian byte representation
	// s.t. element = Σ_{i=0}^{k-1} (input[i] << 8*(k-i-1) ). The input must be exactly
	// FieldBytes long.
	// WARNING: do not use it for uniform sampling, use SetBytesWide instead.
	SetBytes(bytes []byte) (E, error)
	// SetBytesWide creates an element from uniformly sampled bytes, reducing the result
	// with S.Order(). The input must be at most k*WideFieldBytes long.
	SetBytesWide(bytes []byte) (E, error)
}

type BytesSerializationLE[E Element] interface {
	BytesLE() []byte
	SetBytesLE(bytes []byte) (E, error)
	SetBytesWideLE(bytes []byte) (E, error)
}
