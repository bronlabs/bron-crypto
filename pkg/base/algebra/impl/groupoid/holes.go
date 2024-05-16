package groupoid

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/set"
	"github.com/cronokirby/saferith"
)

type HolesGroupoid[G algebra.Groupoid[G, E], E algebra.GroupoidElement[G, E]] interface {
	Cardinality() *saferith.Modulus
	GetOperator(op algebra.Operator) (algebra.BinaryOperator[E], bool)
}

type HolesGroupoidElement[G algebra.Groupoid[G, E], E algebra.GroupoidElement[G, E]] interface {
	Structure() G
	Unwrap() E
	Clone() E
}

type HolesAdditiveGroupoid[G algebra.AdditiveGroupoid[G, E], E algebra.AdditiveGroupoidElement[G, E]] interface {
	HolesGroupoid[G, E]
	Addition() algebra.Addition[E]
}

type HolesAdditiveGroupoidElement[G algebra.AdditiveGroupoid[G, E], E algebra.AdditiveGroupoidElement[G, E]] interface {
	HolesGroupoidElement[G, E]
	Add(x algebra.AdditiveGroupoidElement[G, E]) E
}

type HolesMultiplicativeGroupoid[G algebra.MultiplicativeGroupoid[G, E], E algebra.MultiplicativeGroupoidElement[G, E]] interface {
	HolesGroupoid[G, E]
	Multiplication() algebra.Multiplication[E]
}

type HolesMultiplicativeGroupoidElement[G algebra.MultiplicativeGroupoid[G, E], E algebra.MultiplicativeGroupoidElement[G, E]] interface {
	HolesGroupoidElement[G, E]
	Mul(x algebra.MultiplicativeGroupoidElement[G, E]) E
}

type HolesCyclicGroupoid[G algebra.CyclicGroupoid[G, E], E algebra.CyclicGroupoidElement[G, E]] interface {
	HolesGroupoid[G, E]
	BasePoint() E
}

type HolesCyclicGroupoidElement[G algebra.CyclicGroupoid[G, E], E algebra.CyclicGroupoidElement[G, E]] interface {
	HolesGroupoidElement[G, E]
	set.HolesPointedSetElement[G, E]
}

func NewGroupoid[G algebra.Groupoid[G, E], E algebra.GroupoidElement[G, E]](H HolesGroupoid[G, E]) Groupoid[G, E] {
	return Groupoid[G, E]{
		H: H,
	}
}
func NewGroupoidElement[G algebra.Groupoid[G, E], E algebra.GroupoidElement[G, E]](H HolesGroupoidElement[G, E]) GroupoidElement[G, E] {
	return GroupoidElement[G, E]{
		H: H,
	}
}

func NewAdditiveGroupoid[G algebra.AdditiveGroupoid[G, E], E algebra.AdditiveGroupoidElement[G, E]](H HolesAdditiveGroupoid[G, E]) AdditiveGroupoid[G, E] {
	return AdditiveGroupoid[G, E]{
		Groupoid: NewGroupoid(H),
		H:        H,
	}
}

func NewAdditiveGroupoidElement[G algebra.AdditiveGroupoid[G, E], E algebra.AdditiveGroupoidElement[G, E]](H HolesAdditiveGroupoidElement[G, E]) AdditiveGroupoidElement[G, E] {
	return AdditiveGroupoidElement[G, E]{
		GroupoidElement: NewGroupoidElement(H),
		H:               H,
	}
}

func NewMultiplicativeGroupoid[G algebra.MultiplicativeGroupoid[G, E], E algebra.MultiplicativeGroupoidElement[G, E]](H HolesMultiplicativeGroupoid[G, E]) MultiplicativeGroupoid[G, E] {
	return MultiplicativeGroupoid[G, E]{
		Groupoid: NewGroupoid(H),
		H:        H,
	}
}

func NewMultiplicativeGroupoidElement[G algebra.MultiplicativeGroupoid[G, E], E algebra.MultiplicativeGroupoidElement[G, E]](H HolesMultiplicativeGroupoidElement[G, E]) MultiplicativeGroupoidElement[G, E] {
	return MultiplicativeGroupoidElement[G, E]{
		GroupoidElement: NewGroupoidElement(H),
		H:               H,
	}
}

func NewCyclicGroupoid[G algebra.CyclicGroupoid[G, E], E algebra.CyclicGroupoidElement[G, E]](H HolesCyclicGroupoid[G, E]) CyclicGroupoid[G, E] {
	return CyclicGroupoid[G, E]{
		Groupoid: NewGroupoid(H),
		H:        H,
	}
}

func NewCyclicGroupoidElement[G algebra.CyclicGroupoid[G, E], E algebra.CyclicGroupoidElement[G, E]](H HolesCyclicGroupoidElement[G, E]) CyclicGroupoidElement[G, E] {
	return CyclicGroupoidElement[G, E]{
		GroupoidElement:   NewGroupoidElement(H),
		PointedSetElement: set.NewPointedSetElement(H),
		H:                 H,
	}
}
