package algebra

// Monoid defines methods needed for S to be considered as a Monoid.
// Monoid is a Groupoid that's associative and has an identity element.
type Monoid[M Structure, E Element] interface {
	// Monoid is a Groupoid.
	Groupoid[M, E]
	// Identity returns identity element of type E of structure S.
	Identity(under Operator) (E, error)
}

// MonoidElement defines methods for E to be considered as element of S
// where S is a monoid.
// Monoid is a Groupoid that's associative and has an identity element.
type MonoidElement[M Structure, E Element] interface {
	// Monoid element is a groupoid element.
	GroupoidElement[M, E]
	// IsIdentity returns true if this element is the identity element of monoid S.
	IsIdentity(under Operator) (bool, error)
}

// AdditiveMonoid defines additional methods for the monoid S if the operator is some
// form of addition.
type AdditiveMonoid[M Structure, E Element] interface {
	Monoid[M, E]
	// Additive monoid is an additive groupoid.
	AdditiveGroupoid[M, E]
	// AdditiveIdentity returns the identity element of the additive monoid S.
	AdditiveIdentity() E
}

// AdditiveMonoidElement defines additional methods for elements of type E of monoid S if
// the operator is some form of addition.
type AdditiveMonoidElement[M Structure, E Element] interface {
	MonoidElement[M, E]
	// Additive monoid element is an additive groupoid element.
	AdditiveGroupoidElement[M, E]
	// IsAdditiveIdentity returns true if this element is the identity element of additive monoid S.
	IsAdditiveIdentity() bool
}

// MultiplicativeMonoid defines additional methods for elements of type E of monoid S if
// the operator is some form of multiplication.
type MultiplicativeMonoid[M Structure, E Element] interface {
	Monoid[M, E]
	// Multiplicative monoid is an multiplicative groupoid.
	MultiplicativeGroupoid[M, E]
	// MultiplicativeIdentity returns the identity element of the multiplicative monoid S.
	MultiplicativeIdentity() E
}

// MultiplicativeMonoidElement defines additional methods for elements of type E of monoid S if
// the operator is some form of multiplication.
type MultiplicativeMonoidElement[M Structure, E Element] interface {
	MonoidElement[M, E]
	// Multiplicative monoid element is an multiplicative groupoid element.
	MultiplicativeGroupoidElement[M, E]
	// IsMultiplicativeIdentity returns true if this element is the identity element of multiplicative monoid S.
	IsMultiplicativeIdentity() bool
}

type CyclicMonoid[M Structure, E Element] interface {
	Monoid[M, E]
	CyclicGroupoid[M, E]
}

type CyclicMonoidElement[M Structure, E Element] interface {
	MonoidElement[M, E]
	CyclicGroupoidElement[M, E]
}
