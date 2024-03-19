package uints

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
)

type UintLike[U any] interface {
	Add(x U) U
	Sub(x U) U
	Mul(x U) U
	Neg() U
	And(x U) U
	Or(x U) U
	Xor(x U) U
	Not() U
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
