package algebra

import (
	"github.com/cronokirby/saferith"
)

// Ring defines methods needed for S to be considered as a ring.
// A ring (R, +, *) is a structure where (R, +) is a group and (R, *) is a monoid and * distributes wrt +.
type Ring[R Structure, E Element] interface {
	// Ring is a structured set.
	StructuredSet[R, E]

	// Ring has methods of additive group.
	AdditiveGroup[R, E]
	// Ring has methods of multiplicative monoid.
	MultiplicativeMonoid[R, E]

	// QuadraticResidue outputs q where p^2 = q (mod S.Order()) and returns an error if q does not exist.
	QuadraticResidue(p RingElement[R, E]) (E, error)
	// Characteristic returns the smallest positive number of copies of the multiplicative identity that will sum to additive identity.
	// Returns 0 if no such number exists.
	Characteristic() *saferith.Nat
}

// RingElement defines methods needed for elements of type E to be elements of ring S.
// A ring (R, +, *) is a structure where (R, +) is a group and (R, *) is a monoid and * distributes wrt +.
type RingElement[R Structure, E Element] interface {
	// Ring element is an element of a structured set.
	StructuredSetElement[R, E]
	// Ring element is an element of an additive group.
	AdditiveGroupElement[R, E]
	// Ring element is an element of a multiplicative group.
	MultiplicativeMonoidElement[R, E]

	// MulAdd returns the value of this.Mul(p).Add(q)
	MulAdd(p, q RingElement[R, E]) E

	// Sqrt outputs quadrathic residue of this element ie. outputs q where p^2 = q (mod S.Order()) and returns an error if q does not exist.
	Sqrt() (E, error)
}

type FiniteRing[R Structure, E Element] interface {
	FiniteStructure
	Ring[R, E]
}

type FiniteRingElement[R Structure, E Element] interface {
	RingElement[R, E]
	BytesSerialization[E]
}
