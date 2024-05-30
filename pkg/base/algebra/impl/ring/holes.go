package ring

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/monoid"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
)

type HolesSemiRing[R algebra.SemiRing[R, E], E algebra.SemiRingElement[R, E]] interface {
	groupoid.HolesAdditiveGroupoid[R, E]
	monoid.HolesMultiplicativeMonoid[R, E]
}

type HolesSemiRingElement[R algebra.SemiRing[R, E], E algebra.SemiRingElement[R, E]] interface {
	groupoid.HolesAdditiveGroupoidElement[R, E]
	monoid.HolesMultiplicativeMonoidElement[R, E]
}

type HolesFactorialSemiRing[R algebra.FactorialSemiRing[R, E], E algebra.FactorialSemiRingElement[R, E]] interface {
	HolesSemiRing[R, E]
}

type HolesFactorialSemiRingElement[R algebra.FactorialSemiRing[R, E], E algebra.FactorialSemiRingElement[R, E]] interface {
	HolesSemiRingElement[R, E]
	GCD(x E) (E, error)
	Factorise() ds.Map[E, int]
}

type HolesRig[R algebra.Rig[R, E], E algebra.RigElement[R, E]] interface {
	HolesSemiRing[R, E]
	monoid.HolesAdditiveMonoid[R, E]
	monoid.HolesMultiplicativeMonoid[R, E]
}

type HolesRigElement[R algebra.Rig[R, E], E algebra.RigElement[R, E]] interface {
	HolesSemiRingElement[R, E]
	monoid.HolesAdditiveMonoidElement[R, E]
	monoid.HolesMultiplicativeMonoidElement[R, E]
}

type HolesEuclideanRig[R algebra.EuclideanRig[R, E], E algebra.EuclideanRigElement[R, E]] interface {
	HolesRig[R, E]
	HolesFactorialSemiRing[R, E]
}

type HolesEuclideanRigElement[R algebra.EuclideanRig[R, E], E algebra.EuclideanRigElement[R, E]] interface {
	HolesRigElement[R, E]
	HolesFactorialSemiRingElement[R, E]
}

type HolesFiniteEuclideanRig[R algebra.FiniteEuclideanRig[R, E], E algebra.FiniteEuclideanRigElement[R, E]] interface {
	HolesEuclideanRig[R, E]
}

type HolesFiniteEuclideanRigElement[R algebra.FiniteEuclideanRig[R, E], E algebra.FiniteEuclideanRigElement[R, E]] interface {
	HolesEuclideanRigElement[R, E]
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

type HolesEuclideanDomain[R algebra.EuclideanDomain[R, E], E algebra.EuclideanDomainElement[R, E]] interface {
	HolesRing[R, E]
	HolesEuclideanRig[R, E]
}

type HolesEuclideanDomainElement[R algebra.EuclideanDomain[R, E], E algebra.EuclideanDomainElement[R, E]] interface {
	HolesRingElement[R, E]
	HolesEuclideanRigElement[R, E]
}

type HolesFiniteEuclideanDomain[R algebra.FiniteEuclideanDomain[R, E], E algebra.FiniteEuclideanDomainElement[R, E]] interface {
	HolesFiniteRing[R, E]
	HolesFiniteEuclideanRig[R, E]
}

type HolesFiniteEuclideanDomainElement[R algebra.FiniteEuclideanDomain[R, E], E algebra.FiniteEuclideanDomainElement[R, E]] interface {
	HolesFiniteRingElement[R, E]
	HolesFiniteEuclideanRigElement[R, E]
}

func NewSemiRing[R algebra.SemiRing[R, E], E algebra.SemiRingElement[R, E]](H HolesSemiRing[R, E]) SemiRing[R, E] {
	return SemiRing[R, E]{
		AdditiveGroupoid:     groupoid.NewAdditiveGroupoid(H),
		MultiplicativeMonoid: monoid.NewMultiplicativeMonoid(H),
		H:                    H,
	}
}

func NewSemiRingElement[R algebra.SemiRing[R, E], E algebra.SemiRingElement[R, E]](H HolesSemiRingElement[R, E]) SemiRingElement[R, E] {
	return SemiRingElement[R, E]{
		AdditiveGroupoidElement:     groupoid.NewAdditiveGroupoidElement(H),
		MultiplicativeMonoidElement: monoid.NewMultiplicativeMonoidElement(H),
		H:                           H,
	}
}

func NewFactorialSemiRing[R algebra.FactorialSemiRing[R, E], E algebra.FactorialSemiRingElement[R, E]](H HolesFactorialSemiRing[R, E]) FactorialSemiRing[R, E] {
	return FactorialSemiRing[R, E]{
		SemiRing: NewSemiRing(H),
		H:        H,
	}
}

func NewFactorialSemiRingElement[R algebra.FactorialSemiRing[R, E], E algebra.FactorialSemiRingElement[R, E]](H HolesFactorialSemiRingElement[R, E]) FactorialSemiRingElement[R, E] {
	return FactorialSemiRingElement[R, E]{
		SemiRingElement: NewSemiRingElement(H),
		H:               H,
	}
}

func NewRig[R algebra.Rig[R, E], E algebra.RigElement[R, E]](H HolesRig[R, E]) Rig[R, E] {
	return Rig[R, E]{
		SemiRing:       NewSemiRing(H),
		AdditiveMonoid: monoid.NewAdditiveMonoid(H),
		H:              H,
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

func NewEuclideanRig[R algebra.EuclideanRig[R, E], E algebra.EuclideanRigElement[R, E]](H HolesEuclideanRig[R, E]) EuclideanRig[R, E] {
	return EuclideanRig[R, E]{
		Rig:               NewRig(H),
		FactorialSemiRing: NewFactorialSemiRing(H),
		H:                 H,
	}
}

func NewEuclideanRigElement[R algebra.EuclideanRig[R, E], E algebra.EuclideanRigElement[R, E]](H HolesEuclideanRigElement[R, E]) EuclideanRigElement[R, E] {
	return EuclideanRigElement[R, E]{
		RigElement:               NewRigElement(H),
		FactorialSemiRingElement: NewFactorialSemiRingElement(H),
		H:                        H,
	}
}

func NewFiniteEuclideanRig[R algebra.FiniteEuclideanRig[R, E], E algebra.FiniteEuclideanRigElement[R, E]](H HolesFiniteEuclideanRig[R, E]) FiniteEuclideanRig[R, E] {
	return FiniteEuclideanRig[R, E]{
		EuclideanRig: NewEuclideanRig(H),
		H:            H,
	}
}

func NewFiniteEuclideanRigElement[R algebra.FiniteEuclideanRig[R, E], E algebra.FiniteEuclideanRigElement[R, E]](H HolesFiniteEuclideanRigElement[R, E]) FiniteEuclideanRigElement[R, E] {
	return FiniteEuclideanRigElement[R, E]{
		EuclideanRigElement: NewEuclideanRigElement(H),
		H:                   H,
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
		EuclideanRig: NewEuclideanRig(H),
		Ring:         NewRing(H),
		H:            H,
	}
}

func NewEuclideanDomainElement[D algebra.EuclideanDomain[D, E], E algebra.EuclideanDomainElement[D, E]](H HolesEuclideanDomainElement[D, E]) EuclideanDomainElement[D, E] {
	return EuclideanDomainElement[D, E]{
		EuclideanRigElement: NewEuclideanRigElement(H),
		RingElement:         NewRingElement(H),
		H:                   H,
	}
}

func NewFiniteEuclideanDomain[D algebra.FiniteEuclideanDomain[D, E], E algebra.FiniteEuclideanDomainElement[D, E]](H HolesFiniteEuclideanDomain[D, E]) FiniteEuclideanDomain[D, E] {
	return FiniteEuclideanDomain[D, E]{
		FiniteEuclideanRig: NewFiniteEuclideanRig(H),
		FiniteRing:         NewFiniteRing(H),
		H:                  H,
	}
}

func NewFiniteEuclideanDomainElement[D algebra.FiniteEuclideanDomain[D, E], E algebra.FiniteEuclideanDomainElement[D, E]](H HolesFiniteEuclideanDomainElement[D, E]) FiniteEuclideanDomainElement[D, E] {
	return FiniteEuclideanDomainElement[D, E]{
		FiniteEuclideanRigElement: NewFiniteEuclideanRigElement(H),
		FiniteRingElement:         NewFiniteRingElement(H),
		H:                         H,
	}
}
