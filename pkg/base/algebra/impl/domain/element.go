package domain

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
)

type IntegralDomainElement[D algebra.IntegralDomain[D, E], E algebra.IntegralDomainElement[D, E]] struct {
	ring.RingElement[D, E]
}

type GCDDomainElement[D algebra.GCDDomain[D, E], E algebra.GCDDomainElement[D, E]] struct {
	IntegralDomainElement[D, E]
}

type FactorialRingElement[R algebra.FactorialRing[R, E], E algebra.FactorialRingElement[R, E]] struct {
	GCDDomainElement[R, E]
}

type EuclideanDomainElement[D algebra.EuclideanDomain[D, E], E algebra.EuclideanDomainElement[D, E]] struct {
	FactorialRingElement[D, E]
}
