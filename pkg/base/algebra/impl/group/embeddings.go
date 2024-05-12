package group

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
)

type group[G algebra.Structure, E algebra.Element] struct {
	algebra.Group[G, E]
}
type groupElement[G algebra.Structure, E algebra.Element] struct {
	algebra.GroupElement[G, E]
}
type additiveGroup[G algebra.Structure, E algebra.Element] struct {
	algebra.AdditiveGroup[G, E]
}
type additiveGroupElement[G algebra.Structure, E algebra.Element] struct {
	algebra.AdditiveGroupElement[G, E]
}
type multiplicativeGroup[G algebra.Structure, E algebra.Element] struct {
	algebra.MultiplicativeGroup[G, E]
}
type multiplicativeGroupElement[G algebra.Structure, E algebra.Element] struct {
	algebra.MultiplicativeGroupElement[G, E]
}
type cyclicGroup[G algebra.Group[G, E], E algebra.GroupElement[G, E]] struct {
	algebra.CyclicGroup[G, E]
}
type cyclicGroup2[G algebra.Group[G, E], E algebra.GroupElement[G, E]] struct {
	cyclicGroup[G, E]
	groupoid.Groupoid[G, E]
}
type cyclicGroupElement[G algebra.Structure, E algebra.Element] struct {
	algebra.CyclicGroupElement[G, E]
}
