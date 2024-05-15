package domain

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
)

type IntegralDomain[D algebra.IntegralDomain[D, E], E algebra.IntegralDomainElement[D, E]] struct {
	ring.Ring[D, E]
	H HolesIntegralDomain[D, E]
}

type GCDDomain[D algebra.GCDDomain[D, E], E algebra.GCDDomainElement[D, E]] struct {
	IntegralDomain[D, E]
	H HolesGCDDomain[D, E]
}

type FactorialRing[R algebra.FactorialRing[R, E], E algebra.FactorialRingElement[R, E]] struct {
	GCDDomain[R, E]
	H HolesFactorialRing[R, E]
}

type EuclideanDomain[D algebra.EuclideanDomain[D, E], E algebra.EuclideanDomainElement[D, E]] struct {
	FactorialRing[D, E]
	H HolesEuclideanDomain[D, E]
}
