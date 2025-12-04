package properties4

// BinaryOp represents a binary operation with its algebraic properties.
type BinaryOp[E any] struct {
	// Apply performs the binary operation.
	Apply func(a, b E) E
	// Identity returns the identity element (nil if none).
	Identity func() E
	// Inverse returns the inverse of an element (nil if none).
	Inverse func(E) E
	// Commutative indicates if the operation is commutative.
	Commutative bool
	// Associative indicates if the operation is associative.
	Associative bool
}

// HasIdentity returns true if the operation has an identity element.
func (op *BinaryOp[E]) HasIdentity() bool {
	return op.Identity != nil
}

// HasInverse returns true if elements have inverses.
func (op *BinaryOp[E]) HasInverse() bool {
	return op.Inverse != nil
}

// IsCommutative returns whether the operation is commutative.
func (op *BinaryOp[E]) IsCommutative() bool {
	return op.Commutative
}

// IsAssociative returns whether the operation is associative.
func (op *BinaryOp[E]) IsAssociative() bool {
	return op.Associative
}

// AdditionOp creates an addition operator with the given properties.
func AdditionOp[E any](
	add func(a, b E) E,
	zero func() E,
	neg func(E) E,
) *BinaryOp[E] {
	return &BinaryOp[E]{
		Apply:       add,
		Identity:    zero,
		Inverse:     neg,
		Commutative: true,
		Associative: true,
	}
}

// MultiplicationOp creates a multiplication operator with the given properties.
func MultiplicationOp[E any](
	mul func(a, b E) E,
	one func() E,
	inv func(E) E,
	commutative bool,
) *BinaryOp[E] {
	return &BinaryOp[E]{
		Apply:       mul,
		Identity:    one,
		Inverse:     inv,
		Commutative: commutative,
		Associative: true,
	}
}
