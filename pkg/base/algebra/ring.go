package algebra

import (
	"encoding"
	"encoding/json"

	"github.com/cronokirby/saferith"
)

// AbstractRing defines methods needed for S to be considered as a ring.
// A ring (R, +, *) is a structure where (R, +) is a group and (R, *) is a monoid and * distributes wrt +.
type AbstractRing[S Structure, E Element] interface {
	// Ring is a structured set.
	AbstractStructuredSet[S, E]

	// Ring has methods of additive group.
	AdditiveGroupTrait[S, E]
	// Ring has methods of multiplicative monoid.
	MultiplicativeMonoidTrait[S, E]

	// QuadraticResidue outputs q where p^2 = q (mod S.Order()) and returns an error if q does not exist.
	QuadraticResidue(p E) (E, error)
	// Characteristic returns the smallest positive number of copies of the multiplicative identity that will sum to additive identity.
	// Returns 0 if no such number exists.
	Characteristic() *saferith.Nat
}

// AbstractRingElement defines methods needed for elements of type E to be elements of ring S.
// A ring (R, +, *) is a structure where (R, +) is a group and (R, *) is a monoid and * distributes wrt +.
type AbstractRingElement[S Structure, E Element] interface {
	// Ring element is an element of a structured set.
	AbstractStructuredSetElement[S, E]
	// Ring element is an element of an additive group.
	AdditiveGroupElementTrait[S, E]
	// Ring element is an element of a multiplicative group.
	MultiplicativeMonoidElementTrait[S, E]

	// MulAdd returns the value of this.Mul(p).Add(q)
	MulAdd(p, q E) E

	// Sqrt outputs quadrathic residue of this element ie. outputs q where p^2 = q (mod S.Order()) and returns an error if q does not exist.
	Sqrt() (E, error)

	// Uint64 casts the scalar down to a 64-bit integer. Might overflow.
	Uint64() uint64
	// SetNat returns a new element set to the value of `v mod S.Order()`.
	SetNat(v *saferith.Nat) E
	// Nat casts this element as a Nat.
	Nat() *saferith.Nat
	json.Marshaler
	json.Unmarshaler
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}
