package algebra

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type BitWiseElement[E algebra.Element] interface {
	Lsh(bits uint) E
	Rsh(bits uint) E

	algebra.NatLike[E]
	algebra.BytesSerialization[E]
	algebra.BytesSerializationLE[E]
}
