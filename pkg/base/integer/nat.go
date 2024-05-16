package integer

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

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

type N[S algebra.Structure, E algebra.Element] interface {
	NaturalRig[S, E]
	algebra.LowerBoundedOrderTheoreticLattice[S, E]
}

type Nat[S algebra.Structure, E algebra.Element] interface {
	NaturalRigElement[S, E]
	algebra.LowerBoundedOrderTheoreticLatticeElement[S, E]

	TrySub(x NatPlus[S, E]) (E, error)
}
