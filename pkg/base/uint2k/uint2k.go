package uint2k

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

// TODO: REMOVE

// Ring2k is a ring ℤ/2^kℤ of integers modulo 2^k for some k (e.g., 64, 128, 256).
type Ring2k[S algebra.Structure, E algebra.Element] interface {
	// Ring2k is a ring of integers modulo n=2^k.
	algebra.AbstractZn[S, E]
}

// Element2k is an element of a ring ℤ/2^kℤ of integers modulo 2^k for some k (e.g., 64, 128, 256).
type Element2k[S algebra.Structure, E algebra.Element] interface {
	// Element2k is an element of a ring of integers modulo n=2^k.
	algebra.AbstractIntegerRingElement[S, E]
	// Element2k can be treated as a byte slice (big-endian) of length k/8.
	algebra.BytesSerialization[E]

	Ring2k() S
}
