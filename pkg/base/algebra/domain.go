package algebra

type IntegralDomain[D Structure, E Element] interface {
	Ring[D, E]
	// RandomPrime(prng io.Reader)
}

type IntegralDomainElement[D Structure, E Element] interface {
	RingElement[D, E]
	// IsPrime(prng io.Reader)
}

type FiniteIntegralDomain[D Structure, E Element] interface {
	IntegralDomain[D, E]
	FiniteRing[D, E]
}

type FiniteIntegralDomainElement[D Structure, E Element] interface {
	IntegralDomainElement[D, E]
	FiniteRingElement[D, E]
}

type GCDDomain[D Structure, E Element] interface {
	IntegralDomain[D, E]
	GCD(x E, ys ...E) (E, error)
	LCM(x E, ys ...E) (E, error)
	CoPrime(x E, ys ...E) bool
}

type GCDDomainElement[D Structure, E Element] interface {
	IntegralDomainElement[D, E]
	GCD(x E) (E, error)
	LCM(x E) (E, error)
	CoPrime(x E) bool
}

// TODO: change input type
// type GCDDomain[D Structure, E Element] interface {
// 	IntegralDomain[D, E]
// 	GCD(x GCDDomainElement[D, E], ys ...GCDDomainElement[D, E]) (E, error)
// 	LCM(x GCDDomainElement[D, E], ys ...GCDDomainElement[D, E]) (E, error)
// 	CoPrime(x GCDDomainElement[D, E], ys ...GCDDomainElement[D, E]) bool
// }

// type GCDDomainElement[D Structure, E Element] interface {
// 	IntegralDomainElement[D, E]
// 	GCD(x GCDDomainElement[D, E]) (E, error)
// 	LCM(x GCDDomainElement[D, E]) (E, error)
// 	CoPrime(x GCDDomainElement[D, E]) bool
// }

type FiniteGCDDomain[D Structure, E Element] interface {
	GCDDomain[D, E]
	FiniteIntegralDomain[D, E]
}

type FiniteGCDDomainElement[D Structure, E Element] interface {
	GCDDomainElement[D, E]
	FiniteIntegralDomainElement[D, E]
}

type FactorialRing[R Structure, E Element] interface {
	GCDDomain[R, E]
}

type FactorialRingElement[R Structure, E Element] interface {
	GCDDomainElement[R, E]
	Factorise() []E
}

type FiniteFactorialRing[R Structure, E Element] interface {
	FactorialRing[R, E]
	FiniteGCDDomain[R, E]
}

type FiniteFactorialRingElement[R Structure, E Element] interface {
	FactorialRingElement[R, E]
	FiniteGCDDomainElement[R, E]
}

type EuclideanDomain[D Structure, E Element] interface {
	FactorialRing[D, E]
}

type EuclideanDomainElement[D Structure, E Element] interface {
	FactorialRingElement[D, E]
	// TODO: change input type
	EuclideanDiv(x E) (quotient, reminder E)
}

type FiniteEuclideanDomain[D Structure, E Element] interface {
	EuclideanDomain[D, E]
	FiniteFactorialRing[D, E]
}

type FiniteEuclideanDomainElement[D Structure, E Element] interface {
	EuclideanDomainElement[D, E]
	FiniteFactorialRingElement[D, E]
}
