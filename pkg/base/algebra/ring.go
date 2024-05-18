package algebra

import (
	"io"

	"github.com/cronokirby/saferith"
)

type PreSemiRing[R Structure, E Element] interface {
	AdditiveGroupoid[R, E]
	MultiplicativeGroupoid[R, E]
}

type PreSemiRingElement[R Structure, E Element] interface {
	AdditiveGroupoidElement[R, E]
	MultiplicativeGroupoidElement[R, E]

	MulAdd(p, q PreSemiRingElement[R, E]) E
}

type SemiRing[R Structure, E Element] interface {
	PreSemiRing[R, E]
	AdditiveMonoid[R, E]
	MultiplicativeMonoid[R, E]
	// Characteristic returns the smallest positive number of copies of the multiplicative identity that will sum to additive identity.
	// Returns 0 if no such number exists.
	Characteristic() *saferith.Nat
}

type SemiRingElement[R Structure, E Element] interface {
	PreSemiRingElement[R, E]
	AdditiveMonoidElement[R, E]
	MultiplicativeMonoidElement[R, E]
}

type EuclideanSemiRing[R Structure, E Element] interface {
	SemiRing[R, E]

	GCD(x E, ys ...E) (E, error)
	LCM(x E, ys ...E) (E, error)
	CoPrime(x E, ys ...E) bool
	Factorise() []E
}

type EuclideanSemiRingElement[R Structure, E Element] interface {
	SemiRingElement[R, E]
	GCD(x E) (E, error)
	LCM(x E) (E, error)
	CoPrime(x E) bool
	EuclideanDiv(x E) (quotient, reminder E)

	IsPrime() bool
}

type FiniteEuclideanSemiRing[R Structure, E Element] interface {
	EuclideanSemiRing[R, E]
	FiniteStructure[R, E]

	RandomPrime(prng io.Reader)
}

type FiniteEuclideanSemiRingElement[R Structure, E Element] interface {
	EuclideanSemiRingElement[R, E]
	BytesSerialization[E]
}

// Ring defines methods needed for S to be considered as a ring.
// A ring (R, +, *) is a structure where (R, +) is a group and (R, *) is a monoid and * distributes wrt +.
type Ring[R Structure, E Element] interface {
	SemiRing[R, E]
	// Ring has methods of additive group.
	AdditiveGroup[R, E]
}

// RingElement defines methods needed for elements of type E to be elements of ring S.
// A ring (R, +, *) is a structure where (R, +) is a group and (R, *) is a monoid and * distributes wrt +.
type RingElement[R Structure, E Element] interface {
	SemiRingElement[R, E]
	// Ring element is an element of an additive group.
	AdditiveGroupElement[R, E]

	Sqrt() (E, error)
	// IsUnit() bool
}

type FiniteRing[R Structure, E Element] interface {
	FiniteStructure[R, E]
	Ring[R, E]
	QuadraticResidue(p RingElement[R, E]) (E, error)
}

type FiniteRingElement[R Structure, E Element] interface {
	RingElement[R, E]
	BytesSerialization[E]
}

type EuclideanDomain[D Structure, E Element] interface {
	Ring[D, E]
	EuclideanSemiRing[D, E]
}

type EuclideanDomainElement[D Structure, E Element] interface {
	RingElement[D, E]
	EuclideanSemiRingElement[D, E]
}

type FiniteEuclideanDomain[D Structure, E Element] interface {
	FiniteRing[D, E]
	FiniteEuclideanSemiRing[D, E]
}

type FiniteEuclideanDomainElement[D Structure, E Element] interface {
	FiniteRingElement[D, E]
	FiniteEuclideanSemiRingElement[D, E]
}
