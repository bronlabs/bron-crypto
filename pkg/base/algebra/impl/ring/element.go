package ring

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/monoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type PreSemiRingElement[R algebra.PreSemiRing[R, E], E algebra.PreSemiRingElement[R, E]] struct {
	groupoid.GroupoidElement[R, E]
	groupoid.AdditiveGroupoidElement[R, E]
	groupoid.MultiplicativeGroupoidElement[R, E]

	H HolesPreSemiRingElement[R, E]
}

func (e *PreSemiRingElement[R, E]) MulAdd(p, q algebra.PreSemiRingElement[R, E]) E {
	return e.H.Mul(p).Add(q)
}

type SemiRingElement[R algebra.SemiRing[R, E], E algebra.SemiRingElement[R, E]] struct {
	monoid.MonoidElement[R, E]
	monoid.AdditiveMonoidElement[R, E]
	monoid.MultiplicativeMonoidElement[R, E]

	H HolesSemiRingElement[R, E]
}

type EuclideanSemiRingElement[R algebra.EuclideanSemiRing[R, E], E algebra.EuclideanSemiRingElement[R, E]] struct {
	SemiRingElement[R, E]
	H HolesEuclideanSemiRingElement[R, E]
}

func (e *EuclideanSemiRingElement[R, E]) LCM(x E) (E, error) {
	exGCD, err := e.H.GCD(x)
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not compute gcd")
	}
	q, r := e.H.Mul(x).EuclideanDiv(exGCD)
	if !r.IsAdditiveIdentity() {
		return *new(E), errs.NewFailed("gcd should divide multiples.")
	}
	return q, nil
}

func (e *EuclideanSemiRingElement[R, E]) CoPrime(x E) bool {
	exGCD, err := e.H.GCD(x)
	if err != nil {
		panic(err)
	}
	return exGCD.IsMultiplicativeIdentity()
}

type FiniteEuclideanSemiRingElement[R algebra.FiniteEuclideanSemiRing[R, E], E algebra.FiniteEuclideanSemiRingElement[R, E]] struct {
	EuclideanSemiRingElement[R, E]
	H HolesFiniteEuclideanSemiRingElement[R, E]
}

type RingElement[R algebra.Ring[R, E], E algebra.RingElement[R, E]] struct {
	SemiRingElement[R, E]
	group.GroupElement[R, E]
	group.AdditiveGroupElement[R, E]
	monoid.MultiplicativeMonoidElement[R, E]

	H HolesRingElement[R, E]
}

type FiniteRingElement[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]] struct {
	RingElement[R, E]

	H HolesFiniteRingElement[R, E]
}

type EuclideanDomainElement[R algebra.EuclideanDomain[R, E], E algebra.EuclideanDomainElement[R, E]] struct {
	RingElement[R, E]
	EuclideanSemiRingElement[R, E]
	H HolesEuclideanDomainElement[R, E]
}

type FiniteEuclideanDomainElement[R algebra.FiniteEuclideanDomain[R, E], E algebra.FiniteEuclideanDomainElement[R, E]] struct {
	FiniteRingElement[R, E]
	FiniteEuclideanSemiRingElement[R, E]
	H HolesFiniteEuclideanDomainElement[R, E]
}
