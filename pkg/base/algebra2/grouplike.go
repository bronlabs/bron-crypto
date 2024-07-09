package algebra

import "github.com/cronokirby/saferith"

// ******************** Magma
// === Interfaces

type Magma[M Structure[M, ME, Op], ME MagmaElement[ME], Op BinaryOperator[ME]] interface {
	Structure[M, ME, Op]
}

type MagmaElement[ME Element[ME]] interface {
	Element[ME]
	Op(rhs ME) ME

	Order() (*saferith.Nat, error)
}

// === Aspects

type MagmaticAdditiveness[E any] any

type MagmaElementalAdditiveness[E any] interface {
	Add(rhs E) E
	Double() E
}

type MagmaticMultiplicativeness[E any] any

type MagmaElementalMultiplicativeness[E any] interface {
	Element[E]
	Mul(rhs E) E
	Square() E
	Cube() E
}

type SimExp[ME MagmaElement[ME]] func(bases []ME, exponents []*saferith.Nat) (ME, error)

type MultiBaseExp[ME MagmaElement[ME]] func(bases []ME, exponent *saferith.Nat) ME

type MultiExponentExp[ME MagmaElement[ME]] func(base ME, exponents []*saferith.Nat) ME

// ******************** SemiGroup
// === Interfaces

type SemiGroup[SG Magma[SG, SGE, Op], SGE SemiGroupElement[SGE], Op BinaryOperator[SGE]] interface {
	AssociativeStructure[SGE, Op]
	Magma[SG, SGE, Op]
}

type SemiGroupElement[SGE MagmaElement[SGE]] interface {
	MagmaElement[SGE]
}

// ******************** Monoid
// === Interfaces

type Monoid[M SemiGroup[M, ME, Op], ME MonoidElement[ME], Op BinaryOperator[ME]] interface {
	SemiGroup[M, ME, Op]
	StructureWithIdentity[ME]
}

type MonoidElement[ME SemiGroupElement[ME]] interface {
	SemiGroupElement[ME]
	ElementWithIdentity
}

// === Aspects

type StructureWithIdentity[E any] interface {
	Identity() E
}

type ElementWithIdentity interface {
	IsIdentity() bool
}

type MonoidalAdditiveness[E any] interface {
	MagmaticAdditiveness[E]
	AdditiveIdentity() E
}

type MonoidElementalAdditiveness[E any] interface {
	MagmaElementalAdditiveness[E]
	IsAdditiveIdentity() bool
}

type MonoidalMultiplicativeness[E any] interface {
	MagmaticMultiplicativeness[E]
	MultiplicativeIdentity() E
}

type MonoidElementalMultiplicativeness[E any] interface {
	MagmaElementalMultiplicativeness[E]
	IsMultiplicativeIdentity() bool
}

// ********************** Group
// === Interfaces

type Group[G Monoid[G, GE, Op], GE GroupElement[GE], Op BinaryOperator[GE]] interface {
	Monoid[G, GE, Op]
	InvertibleStructure
}

type GroupElement[GE MonoidElement[GE]] interface {
	MonoidElement[GE]
	ElementOfInvertibleStructure[GE]
}

type AbelianGroup[G Group[G, GE, Op], GE GroupElement[GE], Op BinaryOperator[GE]] interface {
	Group[G, GE, Op]
	CommutativeStructure[GE, Op]
}

type AbelianGroupElement[GE GroupElement[GE]] interface {
	GroupElement[GE]
}

// === Aspects

type InvertibleStructure any

type ElementOfInvertibleStructure[E any] interface {
	Inverse() E
	IsInverse(of E) bool
}

type GroupalAdditiveness[E any] interface {
	MonoidalAdditiveness[E]
}

type GroupElementalAdditiveness[E any] interface {
	MonoidElementalAdditiveness[E]

	AdditiveInverse() E
	IsAdditiveInverse(of E) bool

	Sub(E) E
}

type GroupalMultiplicativeness[E any] interface {
	MonoidalMultiplicativeness[E]
}

type MultiplicativeGroupElementInvertibleness[E any] interface {
	MonoidElementalMultiplicativeness[E]

	MultiplicativeInverse() E
	IsMultiplicativeInverse(of E) bool
}

type GroupElementalMultiplicativeness[E any] interface {
	MultiplicativeGroupElementInvertibleness[E]
	Div(rhs E) E
}
