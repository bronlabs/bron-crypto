package algebra

// ******************** SemiGroup

type SemiGroup[E SemiGroupElement[E]] Structure[E]

type SemiGroupElement[E Element[E]] interface {
	Element[E]

	Op(rhs E) E
	Order() Cardinal
}

type AdditiveSemiGroup[E AdditiveSemiGroupElement[E]] SemiGroup[E]

type AdditiveSemiGroupElement[E SemiGroupElement[E]] interface {
	SemiGroupElement[E]

	Add(rhs E) E
	Double() E
}

type MultiplicativeSemiGroup[E MultiplicativeSemiGroupElement[E]] SemiGroup[E]

type MultiplicativeSemiGroupElement[E SemiGroupElement[E]] interface {
	SemiGroupElement[E]
	Mul(rhs E) E
	Square() E
}

type CyclicSemiGroup[E CyclicSemiGroupElement[E]] interface {
	SemiGroup[E]
	Generator()
}

type CyclicSemiGroupElement[E SemiGroupElement[E]] interface {
	SemiGroupElement[E]
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
}

type UniqueFactorizationMonoid[ME UniqueFactorizationMonoidElement[ME]] Monoid[ME]

type UniqueFactorizationMonoidElement[ME MonoidElement[ME]] interface {
	MonoidElement[ME]
	IsProbablyPrime() bool
}

type MonoidWithZero[ME MonoidWithZeroElement[ME]] interface {
	Monoid[ME]
	Zero() ME
}

type MonoidWithZeroElement[ME MonoidElement[ME]] interface {
	MonoidElement[ME]
	IsZero() bool
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
}] interface {
	GroupElement[E]
	MultiplicativeMonoidElement[E]

	Inv() E
	Div(E) E
}

type MultiplicativeGroupWithZero[E MultiplicativeGroupWithZeroElement[E]] interface {
	Group[E]
	MultiplicativeMonoid[E]
	MonoidWithZero[E]
}

type MultiplicativeGroupWithZeroElement[E interface {
	GroupElement[E]
	MultiplicativeMonoidElement[E]
	MonoidWithZeroElement[E]
}] interface {
	GroupElement[E]
	MultiplicativeMonoidElement[E]
	MonoidWithZeroElement[E]

	TryInv() (E, error)
	TryDiv(E) (E, error)
}

// ************** Extra

type AbelianGroup[E AbelianGroupElement[E, S], S RingElement[S]] Module[E, S]

type AbelianGroupElement[E ModuleElement[E, S], S RingElement[S]] ModuleElement[E, S]

type PrimeGroup[E PrimeGroupElement[E, S], S PrimeFieldElement[S]] interface {
	AbelianGroup[E, S]
	VectorSpace[E, S]
	CyclicSemiGroup[E]
}

type PrimeGroupElement[E AbelianGroupElement[E, S], S PrimeFieldElement[S]] interface {
	AbelianGroupElement[E, S]
	Vector[E, S]
	CyclicSemiGroupElement[E]
}
