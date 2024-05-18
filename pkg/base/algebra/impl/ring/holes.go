package ring

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/monoid"
)

type HolesPreSemiRing[R algebra.PreSemiRing[R, E], E algebra.PreSemiRingElement[R, E]] interface {
	groupoid.HolesAdditiveGroupoid[R, E]
	groupoid.HolesMultiplicativeGroupoid[R, E]
}

type HolesPreSemiRingElement[R algebra.PreSemiRing[R, E], E algebra.PreSemiRingElement[R, E]] interface {
	groupoid.HolesAdditiveGroupoidElement[R, E]
	groupoid.HolesMultiplicativeGroupoidElement[R, E]
}

type HolesSemiRing[R algebra.SemiRing[R, E], E algebra.SemiRingElement[R, E]] interface {
	HolesPreSemiRing[R, E]
	monoid.HolesAdditiveMonoid[R, E]
	monoid.HolesMultiplicativeMonoid[R, E]
}

type HolesSemiRingElement[R algebra.SemiRing[R, E], E algebra.SemiRingElement[R, E]] interface {
	HolesPreSemiRingElement[R, E]
	monoid.HolesAdditiveMonoidElement[R, E]
	monoid.HolesMultiplicativeMonoidElement[R, E]
}

type HolesEuclideanSemiRing[R algebra.EuclideanSemiRing[R, E], E algebra.EuclideanSemiRingElement[R, E]] interface {
	HolesSemiRing[R, E]
}

type HolesEuclideanSemiRingElement[R algebra.EuclideanSemiRing[R, E], E algebra.EuclideanSemiRingElement[R, E]] interface {
	HolesSemiRingElement[R, E]
}

type HolesFiniteEuclideanSemiRing[R algebra.FiniteEuclideanSemiRing[R, E], E algebra.FiniteEuclideanSemiRingElement[R, E]] interface {
	HolesEuclideanSemiRing[R, E]
}

type HolesFiniteEuclideanSemiRingElement[R algebra.FiniteEuclideanSemiRing[R, E], E algebra.FiniteEuclideanSemiRingElement[R, E]] interface {
	HolesEuclideanSemiRingElement[R, E]
}

type HolesRing[R algebra.Ring[R, E], E algebra.RingElement[R, E]] interface {
	HolesSemiRing[R, E]
	group.HolesAdditiveGroup[R, E]
	monoid.HolesMultiplicativeMonoid[R, E]
}

type HolesRingElement[R algebra.Ring[R, E], E algebra.RingElement[R, E]] interface {
	HolesSemiRingElement[R, E]
	group.HolesAdditiveGroupElement[R, E]
	monoid.HolesMultiplicativeMonoidElement[R, E]
}

type HolesFiniteRing[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]] interface {
	HolesRing[R, E]
}

type HolesFiniteRingElement[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]] interface {
	HolesRingElement[R, E]
}

type HolesEuclideanDomain[R algebra.EuclideanDomain[R, E], E algebra.EuclideanDomainElement[R, E]] interface {
	HolesRing[R, E]
	HolesEuclideanSemiRing[R, E]
}

type HolesEuclideanDomainElement[R algebra.EuclideanDomain[R, E], E algebra.EuclideanDomainElement[R, E]] interface {
	HolesRingElement[R, E]
	HolesEuclideanSemiRingElement[R, E]
}

type HolesFiniteEuclideanDomain[R algebra.FiniteEuclideanDomain[R, E], E algebra.FiniteEuclideanDomainElement[R, E]] interface {
	HolesFiniteRing[R, E]
	HolesFiniteEuclideanSemiRing[R, E]
}

type HolesFiniteEuclideanDomainElement[R algebra.FiniteEuclideanDomain[R, E], E algebra.FiniteEuclideanDomainElement[R, E]] interface {
	HolesFiniteRingElement[R, E]
	HolesFiniteEuclideanSemiRingElement[R, E]
}

func NewPreSemiRing[R algebra.PreSemiRing[R, E], E algebra.PreSemiRingElement[R, E]](H HolesPreSemiRing[R, E]) PreSemiRing[R, E] {
	return PreSemiRing[R, E]{
		Groupoid:               groupoid.NewGroupoid(H),
		AdditiveGroupoid:       groupoid.NewAdditiveGroupoid(H),
		MultiplicativeGroupoid: groupoid.NewMultiplicativeGroupoid(H),
		H:                      H,
	}
}

func NewPreSemiRingElement[R algebra.PreSemiRing[R, E], E algebra.PreSemiRingElement[R, E]](H HolesPreSemiRingElement[R, E]) PreSemiRingElement[R, E] {
	return PreSemiRingElement[R, E]{
		GroupoidElement:               groupoid.NewGroupoidElement(H),
		AdditiveGroupoidElement:       groupoid.NewAdditiveGroupoidElement(H),
		MultiplicativeGroupoidElement: groupoid.NewMultiplicativeGroupoidElement(H),
		H:                             H,
	}
}

func NewSemiRing[R algebra.SemiRing[R, E], E algebra.SemiRingElement[R, E]](H HolesSemiRing[R, E]) SemiRing[R, E] {
	return SemiRing[R, E]{
		Monoid:               monoid.NewMonoid(H),
		AdditiveMonoid:       monoid.NewAdditiveMonoid(H),
		MultiplicativeMonoid: monoid.NewMultiplicativeMonoid(H),
		H:                    H,
	}
}

func NewSemiRingElement[R algebra.SemiRing[R, E], E algebra.SemiRingElement[R, E]](H HolesSemiRingElement[R, E]) SemiRingElement[R, E] {
	return SemiRingElement[R, E]{
		MonoidElement:               monoid.NewMonoidElement(H),
		AdditiveMonoidElement:       monoid.NewAdditiveMonoidElement(H),
		MultiplicativeMonoidElement: monoid.NewMultiplicativeMonoidElement(H),
		H:                           H,
	}
}

func NewEuclideanSemiRing[R algebra.EuclideanSemiRing[R, E], E algebra.EuclideanSemiRingElement[R, E]](H HolesEuclideanSemiRing[R, E]) EuclideanSemiRing[R, E] {
	return EuclideanSemiRing[R, E]{
		SemiRing: NewSemiRing(H),
		H:        H,
	}
}

func NewEuclideanSemiRingElement[R algebra.EuclideanSemiRing[R, E], E algebra.EuclideanSemiRingElement[R, E]](H HolesEuclideanSemiRingElement[R, E]) EuclideanSemiRingElement[R, E] {
	return EuclideanSemiRingElement[R, E]{
		SemiRingElement: NewSemiRingElement(H),
		H:               H,
	}
}

func NewFiniteEuclideanSemiRing[R algebra.FiniteEuclideanSemiRing[R, E], E algebra.FiniteEuclideanSemiRingElement[R, E]](H HolesFiniteEuclideanSemiRing[R, E]) FiniteEuclideanSemiRing[R, E] {
	return FiniteEuclideanSemiRing[R, E]{
		EuclideanSemiRing: NewEuclideanSemiRing(H),
		H:                 H,
	}
}

func NewFiniteEuclideanSemiRingElement[R algebra.FiniteEuclideanSemiRing[R, E], E algebra.FiniteEuclideanSemiRingElement[R, E]](H HolesFiniteEuclideanSemiRingElement[R, E]) FiniteEuclideanSemiRingElement[R, E] {
	return FiniteEuclideanSemiRingElement[R, E]{
		EuclideanSemiRingElement: NewEuclideanSemiRingElement(H),
		H:                        H,
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

func NewEuclideanDomain[D algebra.EuclideanDomain[D, E], E algebra.EuclideanDomainElement[D, E]](H HolesEuclideanDomain[D, E]) EuclideanDomain[D, E] {
	return EuclideanDomain[D, E]{
		EuclideanSemiRing: NewEuclideanSemiRing(H),
		Ring:              NewRing(H),
		H:                 H,
	}
}

func NewEuclideanDomainElement[D algebra.EuclideanDomain[D, E], E algebra.EuclideanDomainElement[D, E]](H HolesEuclideanDomainElement[D, E]) EuclideanDomainElement[D, E] {
	return EuclideanDomainElement[D, E]{
		EuclideanSemiRingElement: NewEuclideanSemiRingElement(H),
		RingElement:              NewRingElement(H),
		H:                        H,
	}
}

func NewFiniteEuclideanDomain[D algebra.FiniteEuclideanDomain[D, E], E algebra.FiniteEuclideanDomainElement[D, E]](H HolesFiniteEuclideanDomain[D, E]) FiniteEuclideanDomain[D, E] {
	return FiniteEuclideanDomain[D, E]{
		FiniteEuclideanSemiRing: NewFiniteEuclideanSemiRing(H),
		FiniteRing:              NewFiniteRing(H),
		H:                       H,
	}
}

func NewFiniteEuclideanDomainElement[D algebra.FiniteEuclideanDomain[D, E], E algebra.FiniteEuclideanDomainElement[D, E]](H HolesFiniteEuclideanDomainElement[D, E]) FiniteEuclideanDomainElement[D, E] {
	return FiniteEuclideanDomainElement[D, E]{
		FiniteEuclideanSemiRingElement: NewFiniteEuclideanSemiRingElement(H),
		FiniteRingElement:              NewFiniteRingElement(H),
		H:                              H,
	}
}
