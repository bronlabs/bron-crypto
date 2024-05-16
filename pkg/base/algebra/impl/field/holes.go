package field

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/domain"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
)

type HolesField[F algebra.Field[F, E], E algebra.FieldElement[F, E]] interface {
	domain.HolesEuclideanDomain[F, E]
	group.HolesMultiplicativeGroup[F, E]
}

type HolesFieldElement[F algebra.Field[F, E], E algebra.FieldElement[F, E]] interface {
	domain.HolesEuclideanDomainElement[F, E]
	group.HolesMultiplicativeGroupElement[F, E]
}

type HolesFiniteField[F algebra.FiniteField[F, E], E algebra.FiniteFieldElement[F, E]] interface {
	HolesField[F, E]
	domain.HolesFiniteEuclideanDomain[F, E]
}

type HolesFiniteFieldElement[F algebra.FiniteField[F, E], E algebra.FiniteFieldElement[F, E]] interface {
	HolesFieldElement[F, E]
	domain.HolesFiniteEuclideanDomainElement[F, E]
}

type HolesExtensionField[L algebra.ExtensionField[L, K, LE, KE], K algebra.Field[K, KE], LE algebra.ExtensionFieldElement[L, K, LE, KE], KE algebra.FieldElement[K, KE]] interface {
	HolesField[L, LE]
}

type HolesExtensionFieldElement[L algebra.ExtensionField[L, K, LE, KE], K algebra.Field[K, KE], LE algebra.ExtensionFieldElement[L, K, LE, KE], KE algebra.FieldElement[K, KE]] interface {
	HolesFieldElement[L, LE]
}

func NewField[F algebra.Field[F, E], E algebra.FieldElement[F, E]](H HolesField[F, E]) Field[F, E] {
	return Field[F, E]{
		EuclideanDomain:     domain.NewEuclideanDomain(H),
		MultiplicativeGroup: group.NewMultiplicativeGroup(H),
		H:                   H,
	}
}

func NewFieldElement[F algebra.Field[F, E], E algebra.FieldElement[F, E]](H HolesFieldElement[F, E]) FieldElement[F, E] {
	return FieldElement[F, E]{
		EuclideanDomainElement:     domain.NewEuclideanDomainElement(H),
		MultiplicativeGroupElement: group.NewMultiplicativeGroupElement(H),
		H:                          H,
	}
}

func NewFiniteField[F algebra.FiniteField[F, E], E algebra.FiniteFieldElement[F, E]](H HolesFiniteField[F, E]) FiniteField[F, E] {
	return FiniteField[F, E]{
		Field:                 NewField(H),
		FiniteEuclideanDomain: domain.NewFiniteEuclideanDomain(H),
		H:                     H,
	}
}

func NewFiniteFieldElement[F algebra.FiniteField[F, E], E algebra.FiniteFieldElement[F, E]](H HolesFiniteFieldElement[F, E]) FiniteFieldElement[F, E] {
	return FiniteFieldElement[F, E]{
		FieldElement:                 NewFieldElement(H),
		FiniteEuclideanDomainElement: domain.NewFiniteEuclideanDomainElement(H),
		H:                            H,
	}
}

func NewExtensionField[L algebra.ExtensionField[L, K, LE, KE], K algebra.Field[K, KE], LE algebra.ExtensionFieldElement[L, K, LE, KE], KE algebra.FieldElement[K, KE]](H HolesExtensionField[L, K, LE, KE]) ExtensionField[L, K, LE, KE] {
	return ExtensionField[L, K, LE, KE]{
		Field: NewField(H),
		H:     H,
	}
}

func NewExtensionFieldElement[L algebra.ExtensionField[L, K, LE, KE], K algebra.Field[K, KE], LE algebra.ExtensionFieldElement[L, K, LE, KE], KE algebra.FieldElement[K, KE]](H HolesExtensionFieldElement[L, K, LE, KE]) ExtensionFieldElement[L, K, LE, KE] {
	return ExtensionFieldElement[L, K, LE, KE]{
		FieldElement: NewFieldElement(H),
		H:            H,
	}
}
