package algebra

// ******************** Magma

type Magma[E MagmaElement[E]] interface {
	Structure[E]
	Operator() BinaryOperator[E]
}
type MagmaElement[E Element[E]] interface {
	Element[E]
	Operand[E]

	// Order() Cardinal
}

// ******************** SemiGroup

type SemiGroup[E SemiGroupElement[E]] Magma[E]

type SemiGroupElement[E Element[E]] MagmaElement[E]

type AdditiveSemiGroup[E AdditiveSemiGroupElement[E]] SemiGroup[E]

type AdditiveSemiGroupElement[E SemiGroupElement[E]] interface {
	SemiGroupElement[E]
	Summand[E]

	Double() E
}

type MultiplicativeSemiGroup[E MultiplicativeSemiGroupElement[E]] SemiGroup[E]

type MultiplicativeSemiGroupElement[E SemiGroupElement[E]] interface {
	SemiGroupElement[E]
	Multiplicand[E]

	Square() E
}

type CyclicSemiGroup[E CyclicSemiGroupElement[E]] interface {
	SemiGroup[E]
	NPointedSet[E]
	Generator() E
}

type CyclicSemiGroupElement[E SemiGroupElement[E]] interface {
	SemiGroupElement[E]
	NPointedSetElement[E]
	IsDesignatedGenerator() bool
	CanBeGenerator() bool
}

// ******************** Monoid

type Monoid[ME MonoidElement[ME]] interface {
	SemiGroup[ME]
	OpIdentity() ME
}

type MonoidElement[ME SemiGroupElement[ME]] interface {
	SemiGroupElement[ME]
	IsOpIdentity() bool

	TryOpInv() (ME, error)
}

type AdditiveMonoid[ME AdditiveMonoidElement[ME]] interface {
	Monoid[ME]
	AdditiveSemiGroup[ME]
	Zero() ME
}

type AdditiveMonoidElement[ME MonoidElement[ME]] interface {
	MonoidElement[ME]
	AdditiveSemiGroupElement[ME]
	IsZero() bool

	TryNeg() (ME, error)
	TrySub(ME) (ME, error)
}

type MultiplicativeMonoid[ME MultiplicativeMonoidElement[ME]] interface {
	Monoid[ME]
	MultiplicativeSemiGroup[ME]
	One() ME
}

type MultiplicativeMonoidElement[E MultiplicativeSemiGroupElement[E]] interface {
	MonoidElement[E]
	MultiplicativeSemiGroupElement[E]
	IsOne() bool

	TryInv() (E, error)
	TryDiv(E) (E, error)
}

type UniqueFactorizationMonoid[ME UniqueFactorizationMonoidElement[ME]] Monoid[ME]

type UniqueFactorizationMonoidElement[ME MonoidElement[ME]] interface {
	MonoidElement[ME]
	IsProbablyPrime() bool
}

// ******************** Group

type Group[GE GroupElement[GE]] Monoid[GE]

type GroupElement[GE MonoidElement[GE]] interface {
	MonoidElement[GE]
	OpInv() GE
}

type AdditiveGroup[E AdditiveGroupElement[E]] interface {
	Group[E]
	AdditiveMonoid[E]
}

type AdditiveGroupElement[E GroupElement[E]] interface {
	GroupElement[E]
	AdditiveMonoidElement[E]
	Neg() E

	Sub(E) E
}

type MultiplicativeGroup[E MultiplicativeGroupElement[E]] interface {
	Group[E]
	MultiplicativeMonoid[E]
}

type MultiplicativeGroupElement[E interface {
	GroupElement[E]
	MultiplicativeMonoidElement[E]
	Inv() E
	Div(E) E
}] interface {
	GroupElement[E]
	MultiplicativeMonoidElement[E]
	Inv() E
	Div(E) E
}

// ************** Extra

type AbelianGroup[E AbelianGroupElement[E, S], S IntLike[S]] Module[E, S]

type AbelianGroupElement[E ModuleElement[E, S], S IntLike[S]] ModuleElement[E, S]

type FiniteAbelianGroup[E FiniteAbelianGroupElement[E, S], S UintLike[S]] interface {
	AbelianGroup[E, S]
	FiniteStructure[E]
}

type FiniteAbelianGroupElement[E AbelianGroupElement[E, S], S UintLike[S]] AbelianGroupElement[E, S]

type PrimeGroup[E PrimeGroupElement[E, S], S PrimeFieldElement[S]] interface {
	FiniteAbelianGroup[E, S]
	VectorSpace[E, S]
	CyclicSemiGroup[E]
}

type PrimeGroupElement[E Vector[E, S], S PrimeFieldElement[S]] interface {
	FiniteAbelianGroupElement[E, S]
	Vector[E, S]
	CyclicSemiGroupElement[E]
}

type FiniteAbelianMultiplicativeGroup[GE interface {
	FiniteAbelianGroupElement[GE, S]
	MultiplicativeGroupElement[GE]
}, S UintLike[S]] interface {
	FiniteAbelianGroup[GE, S]
	MultiplicativeGroup[GE]
}

type FiniteAbelianMultiplicativeGroupElement[GE interface {
	FiniteAbelianGroupElement[GE, S]
	MultiplicativeGroupElement[GE]
}, S UintLike[S]] interface {
	FiniteAbelianGroupElement[GE, S]
	MultiplicativeGroupElement[GE]
}
