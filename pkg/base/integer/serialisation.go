package integer

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type ConvertTo[S algebra.Structure, E algebra.Element] interface {
	ToNatPlus() (NatPlus[S, E], error)
	ToNat() (Nat[S, E], error)
	ToInt() Int[S, E]

	ToModular(modulus NatPlus[S, E]) Uint[S, E]
	ToPrimeModular(modulus NatPlus[S, E]) IntP[S, E]
}

type ConvertFrom[S algebra.Structure, E algebra.Element] interface {
	FromNatPlus(v NatPlus[S, E]) (E, error)
	FromNat(v Nat[S, E]) (E, error)
	FromInt(v Int[S, E]) (E, error)

	FromModular(v Uint[S, E]) (E, error)
	FromPrimeModular(v IntP[S, E]) (E, error)
}
