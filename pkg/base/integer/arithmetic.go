package integer

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
)

type Arithmetic[T any] interface {
	Name() string

	WithoutBottom() Arithmetic[T]
	WithBottomAtZero() Arithmetic[T]
	WithBottomAtOne() Arithmetic[T]
	WithBottomAtZeroAndModulus(m T) Arithmetic[T]
	WithSize(size int) Arithmetic[T]

	Clone(x T) T

	Equal(x, y T) bool

	Cmp(x, y T) algebra.Ordering

	Zero() T
	One() T
	Two() T

	IsEven(x T) bool
	IsOdd(x T) bool

	Abs(x T) T
	Next(x T) (T, error)
	Neg(x T) (T, error)
	Inverse(x T) (T, error)

	Add(x, y T) (T, error)
	Sub(x, y T) (T, error)
	Mul(x, y T) (T, error)
	Exp(x, y T) (T, error)
	Mod(x, m T) (T, error)

	Square(x T) (T, error)
	Cube(x T) (T, error)

	Max(x, y T) T
	Min(x, y T) T

	Uint64(x T) uint64
}

type Number[T any] interface {
	Arithmetic() Arithmetic[T]

	AnnouncedLen() int
	TrueLen() uint

	algebra.WrappedElement[T]
	algebra.NatLike[T]
}
