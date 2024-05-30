package algebra

import (
	"io"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/cronokirby/saferith"
)

type SemiRing[R Structure, E Element] interface {
	AdditiveGroupoid[R, E]
	MultiplicativeMonoid[R, E]

	Unit() E
}

type SemiRingElement[R Structure, E Element] interface {
	AdditiveGroupoidElement[R, E]
	MultiplicativeMonoidElement[R, E]

	MulAdd(p, q SemiRingElement[R, E]) E
	IsUnit() bool
}

type FactorialSemiRing[R Structure, E Element] interface {
	SemiRing[R, E]
	CoPrime(x E, ys ...E) bool
	// TODO: remove error type
	GCD(x E, ys ...E) (E, error)
	LCM(x E, ys ...E) (E, error)
}

type FactorialSemiRingElement[R Structure, E Element] interface {
	SemiRingElement[R, E]
	GCD(x E) (E, error)
	LCM(x E) (E, error)
	Factorise() ds.Map[E, int] // TODO: change int
	CoPrime(x E) bool
	// Rename to isProbablyPrime
	IsPrime() bool
}

type Rig[R Structure, E Element] interface {
	SemiRing[R, E]
	AdditiveMonoid[R, E]
	// Characteristic returns the smallest positive number of copies of the multiplicative identity that will sum to additive identity.
	// Returns 0 if no such number exists.
	Characteristic() *saferith.Nat
}

type RigElement[R Structure, E Element] interface {
	SemiRingElement[R, E]
	AdditiveMonoidElement[R, E]
	MultiplicativeMonoidElement[R, E]
}

type EuclideanRig[R Structure, E Element] interface {
	Rig[R, E]
	FactorialSemiRing[R, E]
}

type EuclideanRigElement[R Structure, E Element] interface {
	RigElement[R, E]
	FactorialSemiRingElement[R, E]
	EuclideanDiv(x E) (quotient, reminder E)
}

type FiniteEuclideanRig[R Structure, E Element] interface {
	EuclideanRig[R, E]
	FiniteStructure[R, E]

	RandomPrime(prng io.Reader) E
}

type FiniteEuclideanRigElement[R Structure, E Element] interface {
	EuclideanRigElement[R, E]
	BytesSerialization[E]
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

	Sqrt() (E, error)
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
	EuclideanRig[D, E]
}

type EuclideanDomainElement[D Structure, E Element] interface {
	RingElement[D, E]
	EuclideanRigElement[D, E]
}

type FiniteEuclideanDomain[D Structure, E Element] interface {
	FiniteRing[D, E]
	FiniteEuclideanRig[D, E]
}

type FiniteEuclideanDomainElement[D Structure, E Element] interface {
	FiniteRingElement[D, E]
	FiniteEuclideanRigElement[D, E]
}
