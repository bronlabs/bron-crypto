package monoid

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
)

type HolesMonoid[M algebra.Monoid[M, E], E algebra.MonoidElement[M, E]] interface {
	groupoid.HolesGroupoid[M, E]
	Identity(under algebra.Operator) (algebra.MonoidElement[M, E], error)
}

type HolesMonoidElement[M algebra.Monoid[M, E], E algebra.MonoidElement[M, E]] interface {
	groupoid.HolesGroupoidElement[M, E]
}

type HolesAdditiveMonoid[M algebra.AdditiveMonoid[M, E], E algebra.AdditiveMonoidElement[M, E]] interface {
	HolesMonoid[M, E]
	groupoid.HolesAdditiveGroupoid[M, E]
}

type HolesAdditiveMonoidElement[M algebra.AdditiveMonoid[M, E], E algebra.AdditiveMonoidElement[M, E]] interface {
	HolesMonoidElement[M, E]
	groupoid.HolesAdditiveGroupoidElement[M, E]
	Equal(x E) bool
}

type HolesMultiplicativeMonoid[M algebra.MultiplicativeMonoid[M, E], E algebra.MultiplicativeMonoidElement[M, E]] interface {
	HolesMonoid[M, E]
	groupoid.HolesMultiplicativeGroupoid[M, E]
}

type HolesMultiplicativeMonoidElement[M algebra.MultiplicativeMonoid[M, E], E algebra.MultiplicativeMonoidElement[M, E]] interface {
	HolesMonoidElement[M, E]
	groupoid.HolesMultiplicativeGroupoidElement[M, E]
	Equal(x E) bool
}

type HolesCyclicMonoid[M algebra.CyclicMonoid[M, E], E algebra.CyclicMonoidElement[M, E]] interface {
	HolesMonoid[M, E]
	groupoid.HolesCyclicGroupoid[M, E]
}

type HolesCyclicMonoidElement[M algebra.CyclicMonoid[M, E], E algebra.CyclicMonoidElement[M, E]] interface {
	HolesMonoidElement[M, E]
	groupoid.HolesCyclicGroupoidElement[M, E]
}

func NewMonoid[M algebra.Monoid[M, E], E algebra.MonoidElement[M, E]](H HolesMonoid[M, E]) Monoid[M, E] {
	return Monoid[M, E]{
		Groupoid: groupoid.NewGroupoid(H),
		H:        H,
	}
}
func NewMonoidElement[M algebra.Monoid[M, E], E algebra.MonoidElement[M, E]](H HolesMonoidElement[M, E]) MonoidElement[M, E] {
	return MonoidElement[M, E]{
		GroupoidElement: groupoid.NewGroupoidElement(H),
		H:               H,
	}
}

func NewAdditiveMonoid[M algebra.AdditiveMonoid[M, E], E algebra.AdditiveMonoidElement[M, E]](H HolesAdditiveMonoid[M, E]) AdditiveMonoid[M, E] {
	return AdditiveMonoid[M, E]{
		Monoid:           NewMonoid(H),
		AdditiveGroupoid: groupoid.NewAdditiveGroupoid(H),
		H:                H,
	}
}

func NewAdditiveMonoidElement[M algebra.AdditiveMonoid[M, E], E algebra.AdditiveMonoidElement[M, E]](H HolesAdditiveMonoidElement[M, E]) AdditiveMonoidElement[M, E] {
	return AdditiveMonoidElement[M, E]{
		MonoidElement:           NewMonoidElement(H),
		AdditiveGroupoidElement: groupoid.NewAdditiveGroupoidElement(H),
		H:                       H,
	}
}

func NewMultiplicativeMonoid[M algebra.MultiplicativeMonoid[M, E], E algebra.MultiplicativeMonoidElement[M, E]](H HolesMultiplicativeMonoid[M, E]) MultiplicativeMonoid[M, E] {
	return MultiplicativeMonoid[M, E]{
		Monoid:                 NewMonoid(H),
		MultiplicativeGroupoid: groupoid.NewMultiplicativeGroupoid(H),
		H:                      H,
	}
}

func NewMultiplicativeMonoidElement[M algebra.MultiplicativeMonoid[M, E], E algebra.MultiplicativeMonoidElement[M, E]](H HolesMultiplicativeMonoidElement[M, E]) MultiplicativeMonoidElement[M, E] {
	return MultiplicativeMonoidElement[M, E]{
		MonoidElement:                 NewMonoidElement(H),
		MultiplicativeGroupoidElement: groupoid.NewMultiplicativeGroupoidElement(H),
		H:                             H,
	}
}

func NewCyclicMonoid[M algebra.CyclicMonoid[M, E], E algebra.CyclicMonoidElement[M, E]](H HolesCyclicMonoid[M, E]) CyclicMonoid[M, E] {
	return CyclicMonoid[M, E]{
		Monoid:         NewMonoid(H),
		CyclicGroupoid: groupoid.NewCyclicGroupoid(H),
		H:              H,
	}
}

func NewCyclicMonoidElement[M algebra.CyclicMonoid[M, E], E algebra.CyclicMonoidElement[M, E]](H HolesCyclicMonoidElement[M, E]) CyclicMonoidElement[M, E] {
	return CyclicMonoidElement[M, E]{
		MonoidElement:         NewMonoidElement(H),
		CyclicGroupoidElement: groupoid.NewCyclicGroupoidElement(H),
		H:                     H,
	}
}
