package integer

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type NaturalNumberMonoid[S algebra.Structure, E algebra.Element] interface {
	algebra.Monoid[S, E]
	PositiveNaturalNumberGroupoid[S, E]
	Zero() E

	algebra.ConjunctiveMonoid[S, E]
	algebra.DisjunctiveMonoid[S, E]
	algebra.ExclusiveDisjunctiveGroup[S, E]
}

type NaturalNumberMonoidElement[S algebra.Structure, E algebra.Element] interface {
	algebra.MonoidElement[S, E]
	PositiveNaturalNumberGroupoidElement[S, E]
	IsZero() bool

	algebra.ConjunctiveMonoidElement[S, E]
	algebra.DisjunctiveMonoidElement[S, E]
	algebra.ExclusiveDisjunctiveGroupElement[S, E]
	algebra.BitWiseElement[E]
}

type N[S algebra.Structure, E algebra.Element] interface {
	algebra.Rig[S, E]
	NaturalNumberMonoid[S, E]
}

type Nat[S algebra.Structure, E algebra.Element] interface {
	algebra.RigElement[S, E]
	NaturalNumberMonoidElement[S, E]
}
