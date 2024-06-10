package algebra

import (
	"github.com/cronokirby/saferith"
)

// Also known as nonunital semiring (or a nonunital ring rng without additive inverses), it's a generalisation of a Rig, dropping the
// requirement that an identity must exist (both for addition and for multiplication).

type Rg[R Structure, E Element] interface {
	AdditiveGroupoid[R, E]
	MultiplicativeGroupoid[R, E]
}

type RgElement[R Structure, E Element] interface {
	AdditiveGroupoidElement[R, E]
	MultiplicativeGroupoidElement[R, E]
}

// Also known as semiring (or dioid / double monoid) , it's a generalisation of a Ring, dropping the requirement that each element must
// have an additive inverse.
type Rig[R Structure, E Element] interface {
	Rg[R, E]
	AdditiveMonoid[R, E]
	MultiplicativeMonoid[R, E]
	// Characteristic returns the smallest positive number of copies of the multiplicative identity that will sum to additive identity.
	// Returns 0 if no such number exists.
	Characteristic() *saferith.Nat
}

type RigElement[R Structure, E Element] interface {
	RgElement[R, E]
	AdditiveMonoidElement[R, E]
	MultiplicativeMonoidElement[R, E]

	MulAdd(p, q RingElement[R, E]) E
}

// Ring defines methods needed for S to be considered as a ring.
// A ring (R, +, *) is a structure where (R, +) is a group and (R, *) is a monoid and * distributes wrt +.
type Ring[R Structure, E Element] interface {
	Rig[R, E]
	// Ring has methods of additive group.
	AdditiveGroup[R, E]
}

// RingElement defines methods needed for elements of type E to be elements of ring S.
// A ring (R, +, *) is a structure where (R, +) is a group and (R, *) is a monoid and * distributes wrt +.
type RingElement[R Structure, E Element] interface {
	RigElement[R, E]
	// Ring element is an element of an additive group.
	AdditiveGroupElement[R, E]
}

type FiniteRing[R Structure, E Element] interface {
	FiniteStructure[R, E]
	Ring[R, E]
	// QuadraticResidue outputs q where p^2 = q (mod S.Order()) and returns an error if q does not exist.
	QuadraticResidue(p RingElement[R, E]) (E, error)
}

type FiniteRingElement[R Structure, E Element] interface {
	RingElement[R, E]
	BytesSerialization[E]
	// Sqrt outputs quadratic residue of this element ie. outputs q where p^2 = q (mod S.Order()) and returns an error if q does not exist.
	Sqrt() (E, error)
}
