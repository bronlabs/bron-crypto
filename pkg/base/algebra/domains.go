package algebra

type IntegralDomain[D Structure, E Element] interface {
	Ring[D, E]
	CoPrime(x E, ys ...E) bool
}

type IntegralDomainElement[D Structure, E Element] interface {
	RingElement[D, E]
	CoPrime(x E) bool
}

type GCDDomain[D Structure, E Element] interface {
	IntegralDomain[D, E]
	GCD(x E, ys ...E) (E, error)
	LCM(x E, ys ...E) (E, error)
}

type GCDDomainElement[D Structure, E Element] interface {
	IntegralDomainElement[D, E]
	GCD(x E) (E, error)
	LCM(x E) (E, error)
}

type FactorialRing[R Structure, E Element] interface {
	GCDDomain[R, E]
}

type FactorialRingElement[R Structure, E Element] interface {
	GCDDomainElement[R, E]
	Factorize() []E
}

type EuclideanDomain[D Structure, E Element] interface {
	FactorialRing[D, E]
}

type EuclideanDomainElement[D Structure, E Element] interface {
	FactorialRingElement[D, E]
	EuclideanDiv(x E) (quotient, reminder E)
}
