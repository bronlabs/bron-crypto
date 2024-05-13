package integer

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type PositiveNaturalNumberGroupoid[S algebra.Structure, E algebra.Element] interface {
	algebra.Groupoid[S, E]
	algebra.Chain[S, E]
	New(v uint64) E
	One() E

	Arithmetic() Arithmetic[E]
}

type PositiveNaturalNumberGroupoidElement[S algebra.Structure, E algebra.Element] interface {
	algebra.GroupoidElement[S, E]
	algebra.ChainElement[S, E]

	Mod(modulus PositiveNaturalNumberGroupoidElement[S, E]) (E, error)

	IsOne() bool

	IsEven() bool
	IsOdd() bool

	IsPositive() bool

	Number[E]
}

type NPlus[S algebra.Structure, E algebra.Element] interface {
	algebra.Rg[S, E]
	algebra.LowerBoundedOrderTheoreticLattice[S, E]

	PositiveNaturalNumberGroupoid[S, E]
}

type NatPlus[S algebra.Structure, E algebra.Element] interface {
	algebra.RgElement[S, E]
	algebra.LowerBoundedOrderTheoreticLatticeElement[S, E]

	PositiveNaturalNumberGroupoidElement[S, E]

	TrySub(x NatPlus[S, E]) (E, error)
}
