package uints

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/cronokirby/saferith"
)

type UintLike[U any] interface {
	Add(x U) U
	Sub(x U) U
	Mul(x U) U
	And(x U) U
	Or(x U) U
	Xor(x U) U
	Equal(rhs U) bool
	Cmp(rhs U) algebra.Ordering
	Lsh(bits uint) U
	Rsh(bits uint) U
	Nat() *saferith.Nat
	ToBytesLE() []byte
	ToBytesBE() []byte
	FillBytesLE(buf []byte)
	FillBytesBE(buf []byte)
}
