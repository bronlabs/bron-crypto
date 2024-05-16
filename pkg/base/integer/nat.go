package integer

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type PositiveNaturalRg[S algebra.Structure, E algebra.Element] interface {
	algebra.Rg[S, E]
	algebra.Chain[S, E]
	New(v uint64) E
	One() E

	Arithmetic() Arithmetic[E]
}

type PositiveNaturalRgElement[S algebra.Structure, E algebra.Element] interface {
	algebra.RgElement[S, E]
	algebra.ChainElement[S, E]

	IsOne() bool

	IsEven() bool
	IsOdd() bool

	IsPositive() bool

	Number[E]
}

type NaturalRig[S algebra.Structure, E algebra.Element] interface {
	algebra.Rig[S, E]
	PositiveNaturalRg[S, E]

	Zero() E

	// algebra.ConjunctiveMonoid[S, E]
	// algebra.DisjunctiveMonoid[S, E]
	// algebra.ExclusiveDisjunctiveGroup[S, E]
}

type NaturalRigElement[S algebra.Structure, E algebra.Element] interface {
	algebra.RigElement[S, E]
	PositiveNaturalRgElement[S, E]

	IsZero() bool
	Mod(modulus NaturalRigElement[S, E]) (E, error)

	// algebra.ConjunctiveMonoidElement[S, E]
	// algebra.DisjunctiveMonoidElement[S, E]
	// algebra.ExclusiveDisjunctiveGroupElement[S, E]
	// algebra.BitWiseElement[E]
}

type NPlus[S algebra.Structure, E algebra.Element] interface {
	PositiveNaturalRg[S, E]

	algebra.LowerBoundedOrderTheoreticLattice[S, E]
}

type NatPlus[S algebra.Structure, E algebra.Element] interface {
	PositiveNaturalRgElement[S, E]

	algebra.LowerBoundedOrderTheoreticLatticeElement[S, E]

	TrySub(x NatPlus[S, E]) (E, error)
}

type N[S algebra.Structure, E algebra.Element] interface {
	NaturalRig[S, E]
	algebra.LowerBoundedOrderTheoreticLattice[S, E]
}

type Nat[S algebra.Structure, E algebra.Element] interface {
	NaturalRigElement[S, E]
	algebra.LowerBoundedOrderTheoreticLatticeElement[S, E]

	TrySub(x NatPlus[S, E]) (E, error)
}
