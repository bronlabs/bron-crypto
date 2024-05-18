package ring

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/monoid"
)

type PreSemiRing[R algebra.PreSemiRing[R, E], E algebra.PreSemiRingElement[R, E]] struct {
	groupoid.Groupoid[R, E]
	groupoid.AdditiveGroupoid[R, E]
	groupoid.MultiplicativeGroupoid[R, E]
	H HolesPreSemiRing[R, E]
}

type SemiRing[R algebra.SemiRing[R, E], E algebra.SemiRingElement[R, E]] struct {
	PreSemiRing[R, E]
	monoid.Monoid[R, E]
	monoid.AdditiveMonoid[R, E]
	monoid.MultiplicativeMonoid[R, E]
	H HolesSemiRing[R, E]
}

type EuclideanSemiRing[R algebra.EuclideanSemiRing[R, E], E algebra.EuclideanSemiRingElement[R, E]] struct {
	SemiRing[R, E]
	H HolesEuclideanSemiRing[R, E]
}

type FiniteEuclideanSemiRing[R algebra.FiniteEuclideanSemiRing[R, E], E algebra.FiniteEuclideanSemiRingElement[R, E]] struct {
	EuclideanSemiRing[R, E]
	H HolesFiniteEuclideanSemiRing[R, E]
}

type Ring[R algebra.Ring[R, E], E algebra.RingElement[R, E]] struct {
	SemiRing[R, E]
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
	EuclideanSemiRing[R, E]
	H HolesEuclideanDomain[R, E]
}

type FiniteEuclideanDomain[R algebra.FiniteEuclideanDomain[R, E], E algebra.FiniteEuclideanDomainElement[R, E]] struct {
	FiniteRing[R, E]
	FiniteEuclideanSemiRing[R, E]
	H HolesFiniteEuclideanDomain[R, E]
}
