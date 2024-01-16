package algebra

// AbstractMonoid defines methods needed for S to be considered as a Monoid.
// Monoid is a Groupoid that's associative and has an identity element.
type AbstractMonoid[S Structure, E Element] interface {
	// Monoid is a Groupoid.
	AbstractGroupoid[S, E]
	// Identity returns identity element of type E of structure S.
	Identity() E
}

// AbstractMonoidElement defines methods for E to be considered as element of S
// where S is a monoid.
// Monoid is a Groupoid that's associative and has an identity element.
type AbstractMonoidElement[S Structure, E Element] interface {
	// Monoid element is a groupoid element.
	AbstractGroupoidElement[S, E]
	// IsIdentity returns true if this element is the identity element of monoid S.
	IsIdentity() bool
}

// AdditiveMonoidTrait defines additional methods for the monoid S if the operator is some
// form of addition.
type AdditiveMonoidTrait[S Structure, E Element] interface {
	// Additive monoid is an additive groupoid.
	AdditiveGroupoidTrait[S, E]
	// AdditiveIdentity returns the identity element of the additive monoid S.
	AdditiveIdentity() E
}

// AdditiveMonoidElementTrait defines additional methods for elements of type E of monoid S if
// the operator is some form of addition.
type AdditiveMonoidElementTrait[S Structure, E Element] interface {
	// Additive monoid element is an additive groupoid element.
	AdditiveGroupoidElementTrait[S, E]
	// IsAdditiveIdentity returns true if this element is the identity element of additive monoid S.
	IsAdditiveIdentity() bool
}

// MultiplicativeMonoidTrait defines additional methods for elements of type E of monoid S if
// the operator is some form of multiplication.
type MultiplicativeMonoidTrait[S Structure, E Element] interface {
	// Multiplicative monoid is an multiplicative groupoid.
	MultiplicativeGroupoidTrait[S, E]
	// MultiplicativeIdentity returns the identity element of the multiplicative monoid S.
	MultiplicativeIdentity() E
}

// MultiplicativeMonoidElementTrait defines additional methods for elements of type E of monoid S if
// the operator is some form of multiplication.
type MultiplicativeMonoidElementTrait[S Structure, E Element] interface {
	// Multiplicative monoid element is an multiplicative groupoid element.
	MultiplicativeGroupoidElementTrait[S, E]
	// IsMultiplicativeIdentity returns true if this element is the identity element of multiplicative monoid S.
	IsMultiplicativeIdentity() bool
}
