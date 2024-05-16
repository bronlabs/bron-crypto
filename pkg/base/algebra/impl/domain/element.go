package domain

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
)

type IntegralDomainElement[D algebra.IntegralDomain[D, E], E algebra.IntegralDomainElement[D, E]] struct {
	ring.RingElement[D, E]
	H HolesIntegralDomainElement[D, E]
}

type FiniteIntegralDomainElement[D algebra.FiniteIntegralDomain[D, E], E algebra.FiniteIntegralDomainElement[D, E]] struct {
	ring.FiniteRingElement[D, E]
	H HolesFiniteIntegralDomainElement[D, E]
}

type GCDDomainElement[D algebra.GCDDomain[D, E], E algebra.GCDDomainElement[D, E]] struct {
	IntegralDomainElement[D, E]
	H HolesGCDDomainElement[D, E]
}

type FiniteGCDDomainElement[D algebra.FiniteGCDDomain[D, E], E algebra.FiniteGCDDomainElement[D, E]] struct {
	FiniteIntegralDomainElement[D, E]
	H HolesFiniteGCDDomainElement[D, E]
}

type FactorialRingElement[R algebra.FactorialRing[R, E], E algebra.FactorialRingElement[R, E]] struct {
	GCDDomainElement[R, E]
	H HolesFactorialRingElement[R, E]
}

type FiniteFactorialRingElement[R algebra.FiniteFactorialRing[R, E], E algebra.FiniteFactorialRingElement[R, E]] struct {
	FiniteGCDDomainElement[R, E]
	H HolesFiniteFactorialRingElement[R, E]
}

type EuclideanDomainElement[D algebra.EuclideanDomain[D, E], E algebra.EuclideanDomainElement[D, E]] struct {
	FactorialRingElement[D, E]
	H HolesEuclideanDomainElement[D, E]
}

type FiniteEuclideanDomainElement[D algebra.FiniteEuclideanDomain[D, E], E algebra.FiniteEuclideanDomainElement[D, E]] struct {
	FiniteFactorialRingElement[D, E]
	H HolesFiniteEuclideanDomainElement[D, E]
}
