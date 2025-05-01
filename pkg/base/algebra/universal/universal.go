package universal

import (
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

type Element[E any] ds.Equatable[E]
type CarrierSet[E Element[E]] iter.Seq[E]

type UnaryOperator[E Element[E]] = algebra.UnaryOperator[E]
type BinaryOperator[E Element[E]] = algebra.BinaryOperator[E]

type MixedSortedBinaryOperator[E1 Element[E1], E2 Element[E2]] func(E1, E2) E1

type UnaryProperty[E Element[E]] func(E) bool
type BinaryProperty[E Element[E]] func(E, E) bool
type TernaryProperty[E Element[E]] func(E, E, E) bool

type MixedSortedBinaryProperty[E1 Element[E1], E2 Element[E2]] func(E1, E2) bool
type MixedSortedTernaryProperty[E1 Element[E1], E2 Element[E2]] func(E1, E1, E2) bool

type Signature[E Element[E]] struct {
	DistinguishedElements map[string]E
	UnaryOperators        []UnaryOperator[E]
	BinaryOperators       []BinaryOperator[E]
}

type Axioms[E Element[E]] struct {
	Unary   []UnaryProperty[E]
	Binary  []BinaryProperty[E]
	Ternary []TernaryProperty[E]
}

type MixedAxioms[E1 Element[E1], E2 Element[E2]] struct {
	Binary  []MixedSortedBinaryProperty[E1, E2]
	Ternary []MixedSortedTernaryProperty[E1, E2]
}

type Theory[C CarrierSet[E], E Element[E]] struct {
	CarrierSet C
	Signature  Signature[E]
	Axioms     Axioms[E]
}

type TwoSortedAlgebra[C1 CarrierSet[E1], E1 Element[E1], C2 CarrierSet[E2], E2 Element[E2]] struct {
	First  *Theory[C1, E1]
	Second *Theory[C2, E2]
	Mixed  *MixedAxioms[E1, E2]
}

func Partial[X1, X2, Y any](f func(X1, X2) Y, e X1) func(X2) Y {
	return func(e2 X2) Y {
		return f(e, e2)
	}
}

func InveseElementProperty[E Element[E]](op BinaryOperator[E], identity E, inv UnaryOperator[E]) UnaryProperty[E] {
	return func(x E) bool {
		return op(x, inv(x)).Equal(identity) && op(inv(x), x).Equal(identity)
	}
}

func SemiGroupTheory[C CarrierSet[E], E Element[E]](set C, op BinaryOperator[E]) Theory[C, E] {
	return Theory[C, E]{
		CarrierSet: set,
		Signature: Signature[E]{
			BinaryOperators: []BinaryOperator[E]{op},
		},
		Axioms: Axioms[E]{
			Ternary: []TernaryProperty[E]{op.IsAssociative},
		},
	}
}

func MonoidTheory[C CarrierSet[E], E Element[E]](set C, op BinaryOperator[E], identity E) Theory[C, E] {
	return Theory[C, E]{
		CarrierSet: set,
		Signature: Signature[E]{
			DistinguishedElements: map[string]E{"identity": identity},
			BinaryOperators:       []BinaryOperator[E]{op},
		},
		Axioms: Axioms[E]{
			Unary:   []UnaryProperty[E]{Partial(op.IsAbsorbing, identity)},
			Ternary: []TernaryProperty[E]{op.IsAssociative},
		},
	}
}

func GroupTheory[C CarrierSet[E], E Element[E]](set C, op BinaryOperator[E], inv UnaryOperator[E], identity E) Theory[C, E] {
	return Theory[C, E]{
		CarrierSet: set,
		Signature: Signature[E]{
			DistinguishedElements: map[string]E{"identity": identity},
			BinaryOperators:       []BinaryOperator[E]{op},
			UnaryOperators:        []UnaryOperator[E]{inv},
		},
		Axioms: Axioms[E]{
			Unary:   []UnaryProperty[E]{Partial(op.IsAbsorbing, identity), InveseElementProperty(op, identity, inv)},
			Ternary: []TernaryProperty[E]{op.IsAssociative},
		},
	}
}
