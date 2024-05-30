package ring

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/monoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/cronokirby/saferith"
)

type SemiRingElement[R algebra.SemiRing[R, E], E algebra.SemiRingElement[R, E]] struct {
	groupoid.AdditiveGroupoidElement[R, E]
	monoid.MultiplicativeMonoidElement[R, E]

	H HolesSemiRingElement[R, E]
}

func (e *SemiRingElement[R, E]) MulAdd(p, q algebra.SemiRingElement[R, E]) E {
	return e.H.Mul(p).Add(q)
}

func (e *SemiRingElement[R, E]) IsUnit() bool {
	return e.H.Structure().Unit().Equal(e.H.Unwrap())
}

type FactorialSemiRingElement[R algebra.FactorialSemiRing[R, E], E algebra.FactorialSemiRingElement[R, E]] struct {
	SemiRingElement[R, E]

	H HolesFactorialSemiRingElement[R, E]
}

func (e *FactorialSemiRingElement[R, E]) CoPrime(x E) bool {
	exGCD, err := e.H.GCD(x)
	if err != nil {
		panic(err)
	}
	return exGCD.IsMultiplicativeIdentity()
}

func (e *FactorialSemiRingElement[R, E]) LCM(x E) (E, error) {
	eFactors := e.H.Factorise()
	xFactors := x.Factorise()
	commonFactors := xFactors.Filter(func(xx E) bool {
		return eFactors.ContainsKey(xx)
	})
	var result E
	for _, factor := range commonFactors.Keys() {
		eMultiplicity, exists := eFactors.Get(factor)
		if !exists {
			return *new(E), errs.NewMissing("common factor missing from element")
		}
		xMultiplicity, exists := xFactors.Get(factor)
		if !exists {
			return *new(E), errs.NewMissing("common factor missing from input")
		}
		result = result.Mul(factor.ApplyAdd(factor, new(saferith.Nat).SetUint64(uint64(max(eMultiplicity, xMultiplicity)))))
	}
	return result, nil
}

type RigElement[R algebra.Rig[R, E], E algebra.RigElement[R, E]] struct {
	monoid.MonoidElement[R, E]
	monoid.AdditiveMonoidElement[R, E]
	monoid.MultiplicativeMonoidElement[R, E]

	H HolesRigElement[R, E]
}

func (e *EuclideanRigElement[R, E]) LCM(x E) (E, error) {
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

type EuclideanRigElement[R algebra.EuclideanRig[R, E], E algebra.EuclideanRigElement[R, E]] struct {
	RigElement[R, E]
	FactorialSemiRingElement[R, E]
	H HolesEuclideanRigElement[R, E]
}

type FiniteEuclideanRigElement[R algebra.FiniteEuclideanRig[R, E], E algebra.FiniteEuclideanRigElement[R, E]] struct {
	EuclideanRigElement[R, E]
	H HolesFiniteEuclideanRigElement[R, E]
}

type RingElement[R algebra.Ring[R, E], E algebra.RingElement[R, E]] struct {
	RigElement[R, E]
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
	EuclideanRigElement[R, E]
	H HolesEuclideanDomainElement[R, E]
}

type FiniteEuclideanDomainElement[R algebra.FiniteEuclideanDomain[R, E], E algebra.FiniteEuclideanDomainElement[R, E]] struct {
	FiniteRingElement[R, E]
	FiniteEuclideanRigElement[R, E]
	H HolesFiniteEuclideanDomainElement[R, E]
}
