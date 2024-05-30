package ring

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/monoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type SemiRing[R algebra.SemiRing[R, E], E algebra.SemiRingElement[R, E]] struct {
	groupoid.AdditiveGroupoid[R, E]
	monoid.MultiplicativeMonoid[R, E]
	H HolesSemiRing[R, E]
}

func (r *SemiRing[R, E]) Unit() E {
	return r.MultiplicativeIdentity()
}

type FactorialSemiRing[R algebra.FactorialSemiRing[R, E], E algebra.FactorialSemiRingElement[R, E]] struct {
	SemiRing[R, E]
	H HolesFactorialSemiRing[R, E]
}

func (r *FactorialSemiRing[R, E]) GCD(x E, ys ...E) (E, error) {
	if len(ys) == 0 {
		return x, nil
	}
	var err error
	res := x
	for i, y := range ys {
		res, err = res.GCD(y)
		if err != nil {
			return *new(E), errs.WrapFailed(err, "could not compute gcd at y_%d", i)
		}
	}
	return res, nil
}

func (r *FactorialSemiRing[R, E]) LCM(x E, ys ...E) (E, error) {
	if len(ys) == 0 {
		return x, nil
	}
	var err error
	res := x
	for i, y := range ys {
		res, err = res.LCM(y)
		if err != nil {
			return *new(E), errs.WrapFailed(err, "could not compute gcd at y_%d", i)
		}
	}
	return res, nil
}

func (r *FactorialSemiRing[R, E]) CoPrime(x E, ys ...E) bool {
	out, err := r.GCD(x, ys...)
	if err != nil {
		panic(err)
	}
	return out.IsMultiplicativeIdentity()
}

type Rig[R algebra.Rig[R, E], E algebra.RigElement[R, E]] struct {
	SemiRing[R, E]
	monoid.AdditiveMonoid[R, E]
	H HolesRig[R, E]
}

type EuclideanRig[R algebra.EuclideanRig[R, E], E algebra.EuclideanRigElement[R, E]] struct {
	Rig[R, E]
	FactorialSemiRing[R, E]
	H HolesEuclideanRig[R, E]
}

func (r *EuclideanRig[R, E]) LCM(x E, ys ...E) (E, error) {
	if len(ys) == 0 {
		return x, nil
	}
	var err error
	res := x
	for i, y := range ys {
		res, err = res.LCM(y)
		if err != nil {
			return *new(E), errs.WrapFailed(err, "could not compute gcd at y_%d", i)
		}
	}
	return res, nil
}

type FiniteEuclideanRig[R algebra.FiniteEuclideanRig[R, E], E algebra.FiniteEuclideanRigElement[R, E]] struct {
	EuclideanRig[R, E]
	H HolesFiniteEuclideanRig[R, E]
}

type Ring[R algebra.Ring[R, E], E algebra.RingElement[R, E]] struct {
	Rig[R, E]
	group.Group[R, E]
	group.AdditiveGroup[R, E]
	monoid.MultiplicativeMonoid[R, E]
	H HolesRing[R, E]
}

type FiniteRing[R algebra.FiniteRing[R, E], E algebra.FiniteRingElement[R, E]] struct {
	Ring[R, E]
	H HolesFiniteRing[R, E]
}

type EuclideanDomain[R algebra.EuclideanDomain[R, E], E algebra.EuclideanDomainElement[R, E]] struct {
	Ring[R, E]
	EuclideanRig[R, E]
	H HolesEuclideanDomain[R, E]
}

type FiniteEuclideanDomain[R algebra.FiniteEuclideanDomain[R, E], E algebra.FiniteEuclideanDomainElement[R, E]] struct {
	FiniteRing[R, E]
	FiniteEuclideanRig[R, E]
	H HolesFiniteEuclideanDomain[R, E]
}
