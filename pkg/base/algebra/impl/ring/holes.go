package ring

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/monoid"
)

type HolesRg[R algebra.Rg[R, E], E algebra.RgElement[R, E]] interface {
	groupoid.HolesAdditiveGroupoid[R, E]
	groupoid.HolesMultiplicativeGroupoid[R, E]
}

type HolesRgElement[R algebra.Rg[R, E], E algebra.RgElement[R, E]] interface {
	groupoid.HolesAdditiveGroupoidElement[R, E]
	groupoid.HolesMultiplicativeGroupoidElement[R, E]
}

type HolesRig[R algebra.Rig[R, E], E algebra.RigElement[R, E]] interface {
	HolesRg[R, E]
	monoid.HolesAdditiveMonoid[R, E]
	monoid.HolesMultiplicativeMonoid[R, E]
}

type HolesRigElement[R algebra.Rig[R, E], E algebra.RigElement[R, E]] interface {
	HolesRgElement[R, E]
	monoid.HolesAdditiveMonoidElement[R, E]
	monoid.HolesMultiplicativeMonoidElement[R, E]
}

type HolesRing[R algebra.Ring[R, E], E algebra.RingElement[R, E]] interface {
	HolesRig[R, E]
	group.HolesAdditiveGroup[R, E]
	monoid.HolesMultiplicativeMonoid[R, E]
}

type HolesRingElement[R algebra.Ring[R, E], E algebra.RingElement[R, E]] interface {
	HolesRigElement[R, E]
	group.HolesAdditiveGroupElement[R, E]
	monoid.HolesMultiplicativeMonoidElement[R, E]
}

type HolesFiniteRing[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]] interface {
	HolesRing[R, E]
}

type HolesFiniteRingElement[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]] interface {
	HolesRingElement[R, E]
}

func NewRg[R algebra.Rg[R, E], E algebra.RgElement[R, E]](H HolesRg[R, E]) Rg[R, E] {
	return Rg[R, E]{
		Groupoid:               groupoid.NewGroupoid(H),
		AdditiveGroupoid:       groupoid.NewAdditiveGroupoid(H),
		MultiplicativeGroupoid: groupoid.NewMultiplicativeGroupoid(H),
		H:                      H,
	}
}

func NewRgElement[R algebra.Rg[R, E], E algebra.RgElement[R, E]](H HolesRgElement[R, E]) RgElement[R, E] {
	return RgElement[R, E]{
		GroupoidElement:               groupoid.NewGroupoidElement(H),
		AdditiveGroupoidElement:       groupoid.NewAdditiveGroupoidElement(H),
		MultiplicativeGroupoidElement: groupoid.NewMultiplicativeGroupoidElement(H),
		H:                             H,
	}
}

func NewRig[R algebra.Rig[R, E], E algebra.RigElement[R, E]](H HolesRig[R, E]) Rig[R, E] {
	return Rig[R, E]{
		Monoid:               monoid.NewMonoid(H),
		AdditiveMonoid:       monoid.NewAdditiveMonoid(H),
		MultiplicativeMonoid: monoid.NewMultiplicativeMonoid(H),
		H:                    H,
	}
}

func NewRigElement[R algebra.Rig[R, E], E algebra.RigElement[R, E]](H HolesRigElement[R, E]) RigElement[R, E] {
	return RigElement[R, E]{
		MonoidElement:               monoid.NewMonoidElement(H),
		AdditiveMonoidElement:       monoid.NewAdditiveMonoidElement(H),
		MultiplicativeMonoidElement: monoid.NewMultiplicativeMonoidElement(H),
		H:                           H,
	}
}

func NewRing[R algebra.Ring[R, E], E algebra.RingElement[R, E]](H HolesRing[R, E]) Ring[R, E] {
	return Ring[R, E]{
		Group:                group.NewGroup(H),
		AdditiveGroup:        group.NewAdditiveGroup(H),
		MultiplicativeMonoid: monoid.NewMultiplicativeMonoid(H),
		H:                    H,
	}
}

func NewRingElement[R algebra.Ring[R, E], E algebra.RingElement[R, E]](H HolesRingElement[R, E]) RingElement[R, E] {
	return RingElement[R, E]{
		GroupElement:                group.NewGroupElement(H),
		AdditiveGroupElement:        group.NewAdditiveGroupElement(H),
		MultiplicativeMonoidElement: monoid.NewMultiplicativeMonoidElement(H),
		H:                           H,
	}
}

func NewFiniteRing[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]](H HolesFiniteRing[R, E]) FiniteRing[R, E] {
	return FiniteRing[R, E]{
		Ring: NewRing(H),
		H:    H,
	}
}

func NewFiniteRingElement[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]](H HolesFiniteRingElement[R, E]) FiniteRingElement[R, E] {
	return FiniteRingElement[R, E]{
		RingElement: NewRingElement(H),
		H:           H,
	}
}
