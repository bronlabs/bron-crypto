package impl

import "github.com/bronlabs/bron-crypto/pkg/base/algebra"

type IntegralDomain[D algebra.IntegralDomain[D, E], E algebra.IntegralDomainElement[D, E]] struct {
	algebra.IntegralDomain[D, E]
}

type IntegralDomainElement[D algebra.IntegralDomain[D, E], E algebra.IntegralDomainElement[D, E]] struct {
	algebra.IntegralDomainElement[D, E]
}

type GCDDomain[D algebra.GCDDomain[D, E], E algebra.GCDDomainElement[D, E]] struct {
	algebra.GCDDomain[D, E]
}

type GCDDomainElement[D algebra.GCDDomain[D, E], E algebra.GCDDomainElement[D, E]] struct {
	algebra.GCDDomainElement[D, E]
}

type FactorialRing[R algebra.FactorialRing[R, E], E algebra.FactorialRingElement[R, E]] struct {
	algebra.FactorialRing[R, E]
}

type FactorialRingElement[R algebra.FactorialRing[R, E], E algebra.FactorialRingElement[R, E]] struct {
	algebra.FactorialRingElement[R, E]
}

type EuclideanDomain[D algebra.EuclideanDomain[D, E], E algebra.EuclideanDomainElement[D, E]] struct {
	algebra.EuclideanDomain[D, E]
}

type EuclideanDomainElement[D algebra.EuclideanDomain[D, E], E algebra.EuclideanDomainElement[D, E]] struct {
	algebra.EuclideanDomainElement[D, E]
}
