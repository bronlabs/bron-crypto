package algebra

import "github.com/cronokirby/saferith"

type Negation[E Element] interface {
	UnaryOperator[E]
	Not(x E) E
}

type Conjunction[E Element] interface {
	BinaryOperator[E]
	And(x, y E) E
}

type AlternativeDenial[E Element] interface {
	BinaryOperator[E]
	Nand(x, y E) E
}

type Disjunction[E Element] interface {
	BinaryOperator[E]
	Or(x, y E) E
}

type JointDenial[E Element] interface {
	BinaryOperator[E]
	Nor(x, y E) E
}

type ExclusiveDisjunction[E Element] interface {
	BinaryOperator[E]
	Xor(x, y E) E
}

type BooleanElement[S Structure, E Element] interface {
	StructuredSetElement[S, E]
	Not() E
}

type ConjunctiveGroupoid[G Structure, E Element] interface {
	Groupoid[G, E]
	And(x ConjunctiveGroupoidElement[G, E], ys ...ConjunctiveGroupoidElement[G, E]) E
}

type ConjunctiveGroupoidElement[G Structure, E Element] interface {
	BooleanElement[G, E]
	GroupoidElement[G, E]
	And(x ConjunctiveGroupoidElement[G, E])
	ApplyAnd(x ConjunctiveGroupoidElement[G, E], n *saferith.Nat)
}

type ConjunctiveMonoid[M Structure, E Element] interface {
	Monoid[M, E]
	ConjunctiveGroupoid[M, E]
	ConjunctiveIdentity() E
}

type ConjunctiveMonoidElement[M Structure, E Element] interface {
	BooleanElement[M, E]
	MonoidElement[M, E]
	ConjunctiveGroupoidElement[M, E]
	IsConjunctiveIdentity() bool
}

type DisjunctiveGroupoid[G Structure, E Element] interface {
	Groupoid[G, E]
	Or(x DisjunctiveGroupoidElement[G, E], ys ...DisjunctiveGroupoidElement[G, E]) E
}

type DisjunctiveGroupoidElement[G Structure, E Element] interface {
	BooleanElement[G, E]
	GroupoidElement[G, E]
	Or(x DisjunctiveGroupoidElement[G, E], ys ...DisjunctiveGroupoidElement[G, E])
	ApplyOr(x DisjunctiveGroupoidElement[G, E], n *saferith.Nat)
}

type DisjunctiveMonoid[M Structure, E Element] interface {
	Monoid[M, E]
	DisjunctiveGroupoid[M, E]
	DisjunctiveIdentity() E
}

type DisjunctiveMonoidElement[M Structure, E Element] interface {
	BooleanElement[M, E]
	MonoidElement[M, E]
	DisjunctiveGroupoidElement[M, E]
	IsDisjunctiveIdentity() bool
}

type ExclusiveDisjunctiveGroupoid[G Structure, E Element] interface {
	Groupoid[G, E]
	Xor(x ExclusiveDisjunctiveGroupoidElement[G, E], ys ...ExclusiveDisjunctiveGroupoidElement[G, E]) E
}

type ExclusiveDisjunctiveGroupoidElement[G Structure, E Element] interface {
	BooleanElement[G, E]
	GroupoidElement[G, E]
	Xor(x ExclusiveDisjunctiveGroupoidElement[G, E], ys ...ExclusiveDisjunctiveGroupoidElement[G, E])
	ApplyXor(x ExclusiveDisjunctiveGroupoidElement[G, E], n *saferith.Nat)
}

type ExclusiveDisjunctiveMonoid[M Structure, E Element] interface {
	Monoid[M, E]
	ExclusiveDisjunctiveGroupoid[M, E]
	ExclusiveDisjunctiveIdentity() E
}

type ExclusiveDisjunctiveMonoidElement[M Structure, E Element] interface {
	BooleanElement[M, E]
	MonoidElement[M, E]
	ExclusiveDisjunctiveGroupoidElement[M, E]
	IsExclusiveDisjunctiveIdentity() bool
}

type ExclusiveDisjunctiveGroup[G Structure, E Element] interface {
	Group[G, E]
	ExclusiveDisjunctiveMonoid[G, E]
}

type ExclusiveDisjunctiveGroupElement[G Structure, E Element] interface {
	BooleanElement[G, E]
	GroupElement[G, E]
	ExclusiveDisjunctiveMonoidElement[G, E]
	ExclusiveDisjunctiveInverse() E
	IsExclusiveDisjunctiveInverse(of ExclusiveDisjunctiveGroupElement[G, E]) bool
}
