package domain

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
)

type HolesIntegralDomain[D algebra.IntegralDomain[D, E], E algebra.IntegralDomainElement[D, E]] interface {
	ring.HolesRing[D, E]
}

type HolesIntegralDomainElement[D algebra.IntegralDomain[D, E], E algebra.IntegralDomainElement[D, E]] interface {
	ring.HolesRingElement[D, E]
}

type HolesFiniteIntegralDomain[D algebra.FiniteIntegralDomain[D, E], E algebra.FiniteIntegralDomainElement[D, E]] interface {
	ring.HolesFiniteRing[D, E]
	HolesIntegralDomain[D, E]
}

type HolesFiniteIntegralDomainElement[D algebra.FiniteIntegralDomain[D, E], E algebra.FiniteIntegralDomainElement[D, E]] interface {
	ring.HolesFiniteRingElement[D, E]
	HolesIntegralDomain[D, E]
}

type HolesGCDDomain[D algebra.GCDDomain[D, E], E algebra.GCDDomainElement[D, E]] interface {
	HolesIntegralDomain[D, E]
}

type HolesGCDDomainElement[D algebra.GCDDomain[D, E], E algebra.GCDDomainElement[D, E]] interface {
	HolesIntegralDomainElement[D, E]
}

type HolesFiniteGCDDomain[D algebra.FiniteGCDDomain[D, E], E algebra.FiniteGCDDomainElement[D, E]] interface {
	HolesFiniteIntegralDomain[D, E]
	HolesGCDDomain[D, E]
}

type HolesFiniteGCDDomainElement[D algebra.FiniteGCDDomain[D, E], E algebra.FiniteGCDDomainElement[D, E]] interface {
	HolesFiniteIntegralDomainElement[D, E]
	HolesGCDDomainElement[D, E]
}

type HolesFactorialRing[R algebra.FactorialRing[R, E], E algebra.FactorialRingElement[R, E]] interface {
	HolesGCDDomain[R, E]
}

type HolesFactorialRingElement[R algebra.FactorialRing[R, E], E algebra.FactorialRingElement[R, E]] interface {
	HolesGCDDomainElement[R, E]
}

type HolesFiniteFactorialRing[R algebra.FiniteFactorialRing[R, E], E algebra.FiniteFactorialRingElement[R, E]] interface {
	HolesFiniteGCDDomain[R, E]
	HolesFactorialRing[R, E]
}

type HolesFiniteFactorialRingElement[R algebra.FiniteFactorialRing[R, E], E algebra.FiniteFactorialRingElement[R, E]] interface {
	HolesFiniteGCDDomainElement[R, E]
	HolesFactorialRingElement[R, E]
}

type HolesEuclideanDomain[D algebra.EuclideanDomain[D, E], E algebra.EuclideanDomainElement[D, E]] interface {
	HolesFactorialRing[D, E]
}

type HolesEuclideanDomainElement[D algebra.EuclideanDomain[D, E], E algebra.EuclideanDomainElement[D, E]] interface {
	HolesFactorialRingElement[D, E]
}

type HolesFiniteEuclideanDomain[D algebra.FiniteEuclideanDomain[D, E], E algebra.FiniteEuclideanDomainElement[D, E]] interface {
	HolesFiniteFactorialRing[D, E]
	HolesEuclideanDomain[D, E]
}

type HolesFiniteEuclideanDomainElement[D algebra.FiniteEuclideanDomain[D, E], E algebra.FiniteEuclideanDomainElement[D, E]] interface {
	HolesFiniteFactorialRingElement[D, E]
	HolesEuclideanDomainElement[D, E]
}

func NewIntegralDomain[D algebra.IntegralDomain[D, E], E algebra.IntegralDomainElement[D, E]](H HolesIntegralDomain[D, E]) IntegralDomain[D, E] {
	return IntegralDomain[D, E]{
		Ring: ring.NewRing(H),
		H:    H,
	}
}

func NewIntegralDomainElement[D algebra.IntegralDomain[D, E], E algebra.IntegralDomainElement[D, E]](H HolesIntegralDomainElement[D, E]) IntegralDomainElement[D, E] {
	return IntegralDomainElement[D, E]{
		RingElement: ring.NewRingElement(H),
		H:           H,
	}
}

func NewFiniteIntegralDomain[D algebra.FiniteIntegralDomain[D, E], E algebra.FiniteIntegralDomainElement[D, E]](H HolesFiniteIntegralDomain[D, E]) FiniteIntegralDomain[D, E] {
	return FiniteIntegralDomain[D, E]{
		FiniteRing: ring.NewFiniteRing(H),
		H:          H,
	}
}

func NewFiniteIntegralDomainElement[D algebra.FiniteIntegralDomain[D, E], E algebra.FiniteIntegralDomainElement[D, E]](H HolesFiniteIntegralDomainElement[D, E]) FiniteIntegralDomainElement[D, E] {
	return FiniteIntegralDomainElement[D, E]{
		FiniteRingElement: ring.NewFiniteRingElement(H),
		H:                 H,
	}
}

func NewGCDDomain[D algebra.GCDDomain[D, E], E algebra.GCDDomainElement[D, E]](H HolesGCDDomain[D, E]) GCDDomain[D, E] {
	return GCDDomain[D, E]{
		IntegralDomain: NewIntegralDomain(H),
		H:              H,
	}
}

func NewGCDDomainElement[D algebra.GCDDomain[D, E], E algebra.GCDDomainElement[D, E]](H HolesGCDDomainElement[D, E]) GCDDomainElement[D, E] {
	return GCDDomainElement[D, E]{
		IntegralDomainElement: NewIntegralDomainElement(H),
		H:                     H,
	}
}

func NewFiniteGCDDomain[D algebra.FiniteGCDDomain[D, E], E algebra.FiniteGCDDomainElement[D, E]](H HolesFiniteGCDDomain[D, E]) FiniteGCDDomain[D, E] {
	return FiniteGCDDomain[D, E]{
		FiniteIntegralDomain: NewFiniteIntegralDomain(H),
		H:                    H,
	}
}

func NewFiniteGCDDomainElement[D algebra.FiniteGCDDomain[D, E], E algebra.FiniteGCDDomainElement[D, E]](H HolesFiniteGCDDomainElement[D, E]) FiniteGCDDomainElement[D, E] {
	return FiniteGCDDomainElement[D, E]{
		FiniteIntegralDomainElement: NewFiniteIntegralDomainElement(H),
		H:                           H,
	}
}

func NewFactorialRing[R algebra.FactorialRing[R, E], E algebra.FactorialRingElement[R, E]](H HolesFactorialRing[R, E]) FactorialRing[R, E] {
	return FactorialRing[R, E]{
		GCDDomain: NewGCDDomain(H),
		H:         H,
	}
}

func NewFactorialRingElement[R algebra.FactorialRing[R, E], E algebra.FactorialRingElement[R, E]](H HolesFactorialRingElement[R, E]) FactorialRingElement[R, E] {
	return FactorialRingElement[R, E]{
		GCDDomainElement: NewGCDDomainElement(H),
		H:                H,
	}
}

func NewFiniteFactorialRing[R algebra.FiniteFactorialRing[R, E], E algebra.FiniteFactorialRingElement[R, E]](H HolesFiniteFactorialRing[R, E]) FiniteFactorialRing[R, E] {
	return FiniteFactorialRing[R, E]{
		FiniteGCDDomain: NewFiniteGCDDomain(H),
		H:               H,
	}
}

func NewFiniteFactorialRingElement[R algebra.FiniteFactorialRing[R, E], E algebra.FiniteFactorialRingElement[R, E]](H HolesFiniteFactorialRingElement[R, E]) FiniteFactorialRingElement[R, E] {
	return FiniteFactorialRingElement[R, E]{
		FiniteGCDDomainElement: NewFiniteGCDDomainElement(H),
		H:                      H,
	}
}

func NewEuclideanDomain[D algebra.EuclideanDomain[D, E], E algebra.EuclideanDomainElement[D, E]](H HolesEuclideanDomain[D, E]) EuclideanDomain[D, E] {
	return EuclideanDomain[D, E]{
		FactorialRing: NewFactorialRing(H),
		H:             H,
	}
}

func NewEuclideanDomainElement[D algebra.EuclideanDomain[D, E], E algebra.EuclideanDomainElement[D, E]](H HolesEuclideanDomainElement[D, E]) EuclideanDomainElement[D, E] {
	return EuclideanDomainElement[D, E]{
		FactorialRingElement: NewFactorialRingElement(H),
		H:                    H,
	}
}

func NewFiniteEuclideanDomain[D algebra.FiniteEuclideanDomain[D, E], E algebra.FiniteEuclideanDomainElement[D, E]](H HolesFiniteEuclideanDomain[D, E]) FiniteEuclideanDomain[D, E] {
	return FiniteEuclideanDomain[D, E]{
		FiniteFactorialRing: NewFiniteFactorialRing(H),
		H:                   H,
	}
}

func NewFiniteEuclideanDomainElement[D algebra.FiniteEuclideanDomain[D, E], E algebra.FiniteEuclideanDomainElement[D, E]](H HolesFiniteEuclideanDomainElement[D, E]) FiniteEuclideanDomainElement[D, E] {
	return FiniteEuclideanDomainElement[D, E]{
		FiniteFactorialRingElement: NewFiniteFactorialRingElement(H),
		H:                          H,
	}
}
