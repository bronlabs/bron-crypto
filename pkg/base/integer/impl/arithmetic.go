package impl

import (
	"math/big"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/cronokirby/saferith"
)

type Name string

type Arithmetic[N any] interface {
	Name() Name

	WithoutBottom() Arithmetic[N]
	WithBottomAtZero() Arithmetic[N]
	WithBottomAtOne() Arithmetic[N]
	WithBottomAtZeroAndModulus(m N) Arithmetic[N]
	WithSize(size int) Arithmetic[N]

	Equal(x, y N) bool

	Cmp(x, y N) algebra.Ordering

	Zero() N
	One() N
	Two() N

	IsEven(x N) bool
	IsOdd(x N) bool

	Abs(x N) N
	Next(x N) (N, error)
	Neg(x N) (N, error)
	Inverse(x N) (N, error)

	Add(x, y N) (N, error)
	Sub(x, y N) (N, error)
	Mul(x, y N) (N, error)
	Exp(x, y N) (N, error)
	Mod(x, m N) (N, error)

	Max(x, y N) N
	Min(x, y N) N
}

type Number[T any] interface {
	AnnouncedLen() uint
	TrueLen() uint
	Clone() T
	Unwrap() T

	BigIntHandler[T]
	NatHandler[T]
}

type BigIntHandler[T any] interface {
	Big() *big.Int
	FromBig(*big.Int) T
}
type NatHandler[T any] interface {
	Nat() *saferith.Nat
	FromNat(*saferith.Nat) T
}
