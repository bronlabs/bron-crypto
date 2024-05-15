package group

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/monoid"
)

type HolesGroup[G algebra.Group[G, E], E algebra.GroupElement[G, E]] interface {
	monoid.HolesMonoid[G, E]
}
type HolesGroupElement[G algebra.Group[G, E], E algebra.GroupElement[G, E]] interface {
	monoid.HolesMonoidElement[G, E]
}

type HolesAdditiveGroup[G algebra.AdditiveGroup[G, E], E algebra.AdditiveGroupElement[G, E]] interface {
	HolesGroup[G, E]
	monoid.HolesAdditiveMonoid[G, E]
}

type HolesAdditiveGroupElement[G algebra.AdditiveGroup[G, E], E algebra.AdditiveGroupElement[G, E]] interface {
	HolesGroupElement[G, E]
	monoid.HolesAdditiveMonoidElement[G, E]
	AdditiveInverse() E
}

type HolesMultiplicativeGroup[G algebra.MultiplicativeGroup[G, E], E algebra.MultiplicativeGroupElement[G, E]] interface {
	HolesGroup[G, E]
	monoid.HolesMultiplicativeMonoid[G, E]
}

type HolesMultiplicativeGroupElement[G algebra.MultiplicativeGroup[G, E], E algebra.MultiplicativeGroupElement[G, E]] interface {
	HolesGroupElement[G, E]
	monoid.HolesMultiplicativeMonoidElement[G, E]
	MultiplicativeInverse() (E, error)
}

type HolesCyclicGroup[G algebra.CyclicGroup[G, E], E algebra.CyclicGroupElement[G, E]] interface {
	HolesGroup[G, E]
	monoid.HolesCyclicMonoid[G, E]
}

type HolesCyclicGroupElement[G algebra.CyclicGroup[G, E], E algebra.CyclicGroupElement[G, E]] interface {
	HolesGroupElement[G, E]
	monoid.HolesCyclicMonoidElement[G, E]
}

func NewGroup[M algebra.Group[M, E], E algebra.GroupElement[M, E]](H HolesGroup[M, E]) Group[M, E] {
	return Group[M, E]{
		Monoid: monoid.NewMonoid(H),
		H:      H,
	}
}
func NewGroupElement[M algebra.Group[M, E], E algebra.GroupElement[M, E]](H HolesGroupElement[M, E]) GroupElement[M, E] {
	return GroupElement[M, E]{
		MonoidElement: monoid.NewMonoidElement(H),
		H:             H,
	}
}

func NewAdditiveGroup[M algebra.AdditiveGroup[M, E], E algebra.AdditiveGroupElement[M, E]](H HolesAdditiveGroup[M, E]) AdditiveGroup[M, E] {
	return AdditiveGroup[M, E]{
		Group:          NewGroup(H),
		AdditiveMonoid: monoid.NewAdditiveMonoid(H),
		H:              H,
	}
}

func NewAdditiveGroupElement[M algebra.AdditiveGroup[M, E], E algebra.AdditiveGroupElement[M, E]](H HolesAdditiveGroupElement[M, E]) AdditiveGroupElement[M, E] {
	return AdditiveGroupElement[M, E]{
		GroupElement:          NewGroupElement(H),
		AdditiveMonoidElement: monoid.NewAdditiveMonoidElement(H),
		H:                     H,
	}
}

func NewMultiplicativeGroup[M algebra.MultiplicativeGroup[M, E], E algebra.MultiplicativeGroupElement[M, E]](H HolesMultiplicativeGroup[M, E]) MultiplicativeGroup[M, E] {
	return MultiplicativeGroup[M, E]{
		Group:                NewGroup(H),
		MultiplicativeMonoid: monoid.NewMultiplicativeMonoid(H),
		H:                    H,
	}
}

func NewMultiplicativeGroupElement[M algebra.MultiplicativeGroup[M, E], E algebra.MultiplicativeGroupElement[M, E]](H HolesMultiplicativeGroupElement[M, E]) MultiplicativeGroupElement[M, E] {
	return MultiplicativeGroupElement[M, E]{
		GroupElement:                NewGroupElement(H),
		MultiplicativeMonoidElement: monoid.NewMultiplicativeMonoidElement(H),
		H:                           H,
	}
}

func NewCyclicGroup[M algebra.CyclicGroup[M, E], E algebra.CyclicGroupElement[M, E]](H HolesCyclicGroup[M, E]) CyclicGroup[M, E] {
	return CyclicGroup[M, E]{
		Group:        NewGroup(H),
		CyclicMonoid: monoid.NewCyclicMonoid(H),
		H:            H,
	}
}

func NewCyclicGroupElement[M algebra.CyclicGroup[M, E], E algebra.CyclicGroupElement[M, E]](H HolesCyclicGroupElement[M, E]) CyclicGroupElement[M, E] {
	return CyclicGroupElement[M, E]{
		GroupElement:        NewGroupElement(H),
		CyclicMonoidElement: monoid.NewCyclicMonoidElement(H),
		H:                   H,
	}
}
