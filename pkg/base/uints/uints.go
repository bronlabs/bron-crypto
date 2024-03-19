package uints

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
)

type Set[S algebra.Structure, E algebra.Element] interface {
	algebra.AbstractZn[S, E]
}

type Uint[S algebra.Structure, E algebra.Element] interface {
	algebra.AbstractIntegerRingElement[S, E]
	algebra.NatLike[E]
	algebra.BytesLike[E]
	UintTrait[E]
}

type UintTrait[E algebra.Element] interface {
	And(x E) E
	Or(x E) E
	Xor(x E) E
	Not() E
	Lsh(bits uint) E
	Rsh(bits uint) E
	ToBytesLE() []byte
	ToBytesBE() []byte
	FillBytesLE(buf []byte)
	FillBytesBE(buf []byte)
}
