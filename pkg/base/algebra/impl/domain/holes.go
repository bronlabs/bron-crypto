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

type HolesGCDDomain[D algebra.GCDDomain[D, E], E algebra.GCDDomainElement[D, E]] interface {
	HolesIntegralDomain[D, E]
}

type HolesGCDDomainElement[D algebra.GCDDomain[D, E], E algebra.GCDDomainElement[D, E]] interface {
	HolesIntegralDomainElement[D, E]
}

type HolesFactorialRing[R algebra.FactorialRing[R, E], E algebra.FactorialRingElement[R, E]] interface {
	HolesGCDDomain[R, E]
}

type HolesFactorialRingElement[R algebra.FactorialRing[R, E], E algebra.FactorialRingElement[R, E]] interface {
	HolesGCDDomainElement[R, E]
}

type HolesEuclideanDomain[D algebra.EuclideanDomain[D, E], E algebra.EuclideanDomainElement[D, E]] interface {
	HolesFactorialRing[D, E]
}

type HolesEuclideanDomainElement[D algebra.EuclideanDomain[D, E], E algebra.EuclideanDomainElement[D, E]] interface {
	HolesFactorialRingElement[D, E]
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
