package integer

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type NaturalSemiRing[S algebra.Structure, E algebra.Element] interface {
	algebra.FactorialSemiRing[S, E]
	algebra.Chain[S, E]
	One() E

	Arithmetic() Arithmetic[E]
}

type NaturalSemiRingElement[S algebra.Structure, E algebra.Element] interface {
	algebra.FactorialSemiRingElement[S, E]
	algebra.ChainElement[S, E]

	IsOne() bool

	IsEven() bool
	IsOdd() bool

	IsPositive() bool

	Number[E]
}

type NaturalRig[S algebra.Structure, E algebra.Element] interface {
	algebra.EuclideanRig[S, E]
	NaturalSemiRing[S, E]

	Zero() E

	// algebra.ConjunctiveMonoid[S, E]
	// algebra.DisjunctiveMonoid[S, E]
	// algebra.ExclusiveDisjunctiveGroup[S, E]
}

type NaturalRigElement[S algebra.Structure, E algebra.Element] interface {
	algebra.EuclideanRigElement[S, E]
	NaturalSemiRingElement[S, E]

	IsZero() bool
	Mod(modulus NaturalRigElement[S, E]) (E, error)

	// algebra.ConjunctiveMonoidElement[S, E]
	// algebra.DisjunctiveMonoidElement[S, E]
	// algebra.ExclusiveDisjunctiveGroupElement[S, E]
	// algebra.BitWiseElement[E]
}

type NPlus[S algebra.Structure, E algebra.Element] interface {
	NaturalSemiRing[S, E]
	algebra.LowerBoundedOrderTheoreticLattice[S, E]

	// UnsignedPositiveArithmetic() UnsignedPositiveArithmetic[E]
}

type NatPlus[S algebra.Structure, E algebra.Element] interface {
	NaturalSemiRingElement[S, E]
	algebra.LowerBoundedOrderTheoreticLatticeElement[S, E]
	TrySub(x NatPlus[S, E]) (E, error)
}

type N[S algebra.Structure, E algebra.Element] interface {
	NaturalRig[S, E]
	algebra.LowerBoundedOrderTheoreticLattice[S, E]

	// UnsignedArithmetic() UnsignedArithmetic[E]
}

type Nat[S algebra.Structure, E algebra.Element] interface {
	NaturalRigElement[S, E]
	algebra.LowerBoundedOrderTheoreticLatticeElement[S, E]

	TrySub(x NatPlus[S, E]) (E, error)
}
