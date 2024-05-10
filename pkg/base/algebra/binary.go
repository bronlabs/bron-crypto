package algebra

type LeftShiftOperator[E Element] interface {
	BiFunction[E, uint, E]
	Lsh(x E, bits uint) E
}

type RightShiftOperator[E Element] interface {
	BiFunction[E, uint, E]
	Rsh(x E, bits uint) E
}

type ConditionallySelectable[E Element] interface {
	// Select returns (in constant time) x0 if choice is false, and x1 if choice is true.
	Select(choice bool, x0, x1 E) E
	// TODO: Add later
	// Swap(choice bool, x, y E)
	// Assign(choice bool, x, y0, y1 E) // CMove
}

type BitWiseElement[E Element] interface {
	Lsh(bits uint) E
	Rsh(bits uint) E

	NatLike[E]
	BytesSerialization[E]
	BytesSerializationLE[E]
}
