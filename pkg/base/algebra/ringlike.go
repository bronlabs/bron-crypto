package algebra

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
)

type (
	DoubleMagma[E crtp.DoubleMagmaElement[E]]        crtp.DoubleMagma[E]
	DoubleMagmaElement[E crtp.DoubleMagmaElement[E]] crtp.DoubleMagmaElement[E]
)

type (
	HemiRing[E crtp.HemiRingElement[E]]        crtp.HemiRing[E]
	HemiRingElement[E crtp.HemiRingElement[E]] crtp.HemiRingElement[E]
)

type (
	SemiRing[RE crtp.SemiRingElement[RE]]        crtp.SemiRing[RE]
	SemiRingElement[RE crtp.SemiRingElement[RE]] crtp.SemiRingElement[RE]
)

type (
	Rig[RE crtp.RigElement[RE]]        crtp.Rig[RE]
	RigElement[RE crtp.RigElement[RE]] crtp.RigElement[RE]
)

type (
	EuclideanSemiDomain[RE crtp.EuclideanSemiDomainElement[RE]]        crtp.EuclideanSemiDomain[RE]
	EuclideanSemiDomainElement[RE crtp.EuclideanSemiDomainElement[RE]] crtp.EuclideanSemiDomainElement[RE]
)

type (
	Rng[RE crtp.RngElement[RE]]        crtp.Rng[RE]
	RngElement[RE crtp.RngElement[RE]] crtp.RngElement[RE]
)

type (
	Ring[RE crtp.RingElement[RE]]        = crtp.Ring[RE]
	RingElement[RE crtp.RingElement[RE]] = crtp.RingElement[RE]
)

type (
	EuclideanDomain[RE crtp.EuclideanDomainElement[RE]]        crtp.EuclideanDomain[RE]
	EuclideanDomainElement[RE crtp.EuclideanDomainElement[RE]] crtp.EuclideanDomainElement[RE]
)

type (
	Field[FE crtp.FieldElement[FE]]        = crtp.Field[FE]
	FieldElement[FE crtp.FieldElement[FE]] = crtp.FieldElement[FE]

	FieldExtension[FE crtp.FieldExtensionElement[FE]]        = crtp.FieldExtension[FE]
	FieldExtensionElement[FE crtp.FieldExtensionElement[FE]] = crtp.FieldExtensionElement[FE]

	FiniteField[FE crtp.FiniteFieldElement[FE]]        = crtp.FiniteField[FE]
	FiniteFieldElement[FE crtp.FiniteFieldElement[FE]] = crtp.FiniteFieldElement[FE]
)
