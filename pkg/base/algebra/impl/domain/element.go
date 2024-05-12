package domain

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type IntegralDomainElement[D algebra.IntegralDomain[D, E], E algebra.IntegralDomainElement[D, E]] struct {
	algebra.IntegralDomainElement[D, E]
}

type GCDDomainElement[D algebra.GCDDomain[D, E], E algebra.GCDDomainElement[D, E]] struct {
	algebra.GCDDomainElement[D, E]
}

type FactorialRingElement[R algebra.FactorialRing[R, E], E algebra.FactorialRingElement[R, E]] struct {
	algebra.FactorialRingElement[R, E]
}

type EuclideanDomainElement[D algebra.EuclideanDomain[D, E], E algebra.EuclideanDomainElement[D, E]] struct {
	algebra.EuclideanDomainElement[D, E]
}
