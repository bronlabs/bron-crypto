package integer

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type NaturalPreSemiRing[S algebra.Structure, E algebra.Element] interface {
	algebra.PreSemiRing[S, E]
	algebra.Chain[S, E]
	New(v uint64) E
	One() E
}

type NaturalPreSemiRingElement[S algebra.Structure, E algebra.Element] interface {
	algebra.PreSemiRingElement[S, E]
	algebra.ChainElement[S, E]

	IsOne() bool

	IsEven() bool
	IsOdd() bool

	IsPositive() bool
}

type NaturalSemiRing[S algebra.Structure, E algebra.Element] interface {
	algebra.EuclideanSemiRing[S, E]
	NaturalPreSemiRing[S, E]

	Zero() E

	// algebra.ConjunctiveMonoid[S, E]
	// algebra.DisjunctiveMonoid[S, E]
	// algebra.ExclusiveDisjunctiveGroup[S, E]
}

type NaturalSemiRingElement[S algebra.Structure, E algebra.Element] interface {
	algebra.EuclideanSemiRingElement[S, E]
	NaturalPreSemiRingElement[S, E]

	IsZero() bool
	Mod(modulus NaturalSemiRingElement[S, E]) (E, error)

	// algebra.ConjunctiveMonoidElement[S, E]
	// algebra.DisjunctiveMonoidElement[S, E]
	// algebra.ExclusiveDisjunctiveGroupElement[S, E]
	// algebra.BitWiseElement[E]
}

type NPlus[S algebra.Structure, E algebra.Element] interface {
	NaturalPreSemiRing[S, E]
	algebra.LowerBoundedOrderTheoreticLattice[S, E]

	// UnsignedPositiveArithmetic() UnsignedPositiveArithmetic[E]
}

type NatPlus[S algebra.Structure, E algebra.Element] interface {
	NaturalPreSemiRingElement[S, E]
	algebra.LowerBoundedOrderTheoreticLatticeElement[S, E]

	TrySub(x NatPlus[S, E]) (E, error)
}

type N[S algebra.Structure, E algebra.Element] interface {
	NaturalSemiRing[S, E]
	algebra.LowerBoundedOrderTheoreticLattice[S, E]

	// UnsignedArithmetic() UnsignedArithmetic[E]
}

type Nat[S algebra.Structure, E algebra.Element] interface {
	NaturalSemiRingElement[S, E]
	algebra.LowerBoundedOrderTheoreticLatticeElement[S, E]

	TrySub(x NatPlus[S, E]) (E, error)
}
