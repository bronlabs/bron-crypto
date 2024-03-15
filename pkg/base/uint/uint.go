package uint

import "github.com/cronokirby/saferith"

type UintLike[U any] interface {
	Add(rhs U) U
	Sub(rhs U) U
	Mul(rhs U) U
	Clone() U
	IsZero() bool
	Equals(rhs U) bool
	Cmp(rhs U) int
	And(rhs U) U
	Or(rhs U) U
	Xor(rhs U) U
	Lsh(bits uint) U
	Rsh(bits uint) U
	Nat() *saferith.Nat
	ToBytesLE() []byte
	ToBytesBE() []byte
	FillBytesLE(buf []byte)
	FillBytesBE(buf []byte)
}
