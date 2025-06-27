package algebra

import (
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type (
	DoubleMagma[E aimpl.DoubleMagmaElement[E]]        aimpl.DoubleMagma[E]
	DoubleMagmaElement[E aimpl.DoubleMagmaElement[E]] aimpl.DoubleMagmaElement[E]
)

type (
	HemiRing[E aimpl.HemiRingElement[E]]        aimpl.HemiRing[E]
	HemiRingElement[E aimpl.HemiRingElement[E]] aimpl.HemiRingElement[E]
)

type (
	SemiRing[RE aimpl.SemiRingElement[RE]]        aimpl.SemiRing[RE]
	SemiRingElement[RE aimpl.SemiRingElement[RE]] aimpl.SemiRingElement[RE]
)

type (
	Rig[RE aimpl.RigElement[RE]]        aimpl.Rig[RE]
	RigElement[RE aimpl.RigElement[RE]] aimpl.RigElement[RE]
)

type (
	EuclideanSemiDomain[RE aimpl.EuclideanSemiDomainElement[RE]]        aimpl.EuclideanSemiDomain[RE]
	EuclideanSemiDomainElement[RE aimpl.EuclideanSemiDomainElement[RE]] aimpl.EuclideanSemiDomainElement[RE]
)

type (
	Rng[RE aimpl.RngElement[RE]]        aimpl.Rng[RE]
	RngElement[RE aimpl.RngElement[RE]] aimpl.RngElement[RE]
)

type (
	Ring[RE aimpl.RingElement[RE]]        = aimpl.Ring[RE]
	RingElement[RE aimpl.RingElement[RE]] = aimpl.RingElement[RE]

	FiniteRing[RE aimpl.FiniteRingElement[RE]]        = aimpl.FiniteRing[RE]
	FiniteRingElement[RE aimpl.FiniteRingElement[RE]] = aimpl.FiniteRingElement[RE]
)

type (
	EuclideanDomain[RE aimpl.EuclideanDomainElement[RE]]        aimpl.EuclideanDomain[RE]
	EuclideanDomainElement[RE aimpl.EuclideanDomainElement[RE]] aimpl.EuclideanDomainElement[RE]
)

type (
	Field[FE aimpl.FieldElement[FE]]        = aimpl.Field[FE]
	FieldElement[FE aimpl.FieldElement[FE]] = aimpl.FieldElement[FE]

	FiniteField[FE aimpl.FiniteFieldElement[FE]]        = aimpl.FiniteField[FE]
	FiniteFieldElement[FE aimpl.FiniteFieldElement[FE]] = aimpl.FiniteFieldElement[FE]

	FiniteFieldExtension[FE aimpl.FiniteFieldExtensionElement[FE]]        = aimpl.FiniteFieldExtension[FE]
	FiniteFieldExtensionElement[FE aimpl.FiniteFieldExtensionElement[FE]] = aimpl.FiniteFieldExtensionElement[FE]
)

func IsRing[E any](s Structure[E]) bool {
	_, ok := s.(aimpl.Ring[E])
	return ok
}

func GetRing[RE aimpl.RingElement[RE]](re RE) Ring[RE] {
	r, err := StructureAs[Ring[RE]](re.Structure())
	if err != nil {
		panic(err)
	}
	return r
}

func IsField[E any](s Structure[E]) bool {
	return StructureIs[aimpl.Field[E]](s)
}

func GetField[FE aimpl.FieldElement[FE]](fe FE) Field[FE] {
	f, ok := fe.Structure().(Field[FE])
	if !ok {
		panic(errs.NewType("FieldElement does not have a Field structure"))
	}
	return f
}

func IsFiniteField[E any](s Structure[E]) bool {
	return StructureIs[aimpl.FiniteField[E]](s)
}

func GetFiniteField[FE aimpl.FiniteFieldElement[FE]](fe FE) FiniteField[FE] {
	f, ok := fe.Structure().(aimpl.FiniteField[FE])
	if !ok {
		panic(errs.NewType("FieldElement does not have a FiniteField structure"))
	}
	return f
}

func IsPrimeField[E any](s Structure[E]) bool {
	return StructureIs[aimpl.PrimeField[E]](s)
}

func GetPrimeField[FE aimpl.PrimeFieldElement[FE]](fe FE) PrimeField[FE] {
	f, ok := fe.Structure().(aimpl.PrimeField[FE])
	if !ok {
		panic(errs.NewType("FieldElement does not have a PrimeField structure"))
	}
	return f
}
