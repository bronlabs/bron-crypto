package integer

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type ZnX[G algebra.Structure, E algebra.Element] interface {
	algebra.MultiplicativeGroup[G, E]
	NaturalNumberMonoid[G, E]
}

type IntX[G algebra.Structure, E algebra.Element] interface {
	algebra.MultiplicativeGroupElement[G, E]
	NaturalNumberMonoidElement[G, E]
}
