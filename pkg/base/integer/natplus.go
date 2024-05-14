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

	Mod(modulus PositiveNaturalRgElement[S, E]) (E, error)

	IsOne() bool

	IsEven() bool
	IsOdd() bool

	IsPositive() bool

	Number[E]
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
