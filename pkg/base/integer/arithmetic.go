package integer

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
)

type arithmetic[T any] interface {
}

type Arithmetic[T any] interface {
	New(v uint64) T
	Cmp(x, y T) algebra.Ordering
	IsEven(x T) bool
	IsProbablyPrime(x T) bool

	Neg(x T) (T, error)
	Sqrt(x T) (T, error)
	Mod(x, m T) (T, error)

	Add(x, y T, cap int) (T, error)
	Sub(x, y T, cap int) (T, error)
	Mul(x, y T, cap int) (T, error)
	Div(x, y T, cap int) (quotient, remainder T, err error)

	Exp(x, y T) (T, error)
	SimExp(bases, exponents []T) (T, error)
	MultiBaseExp(bases []T, exponent T) (T, error)
	MultiExponentExp(base T, exponents []T) (T, error)

	Uint64(x T) uint64
}

type ModularArithmetic[T any] interface {
	Arithmetic[T]

	Inverse(x T) (T, error)
	QuadraticResidue(x T) (T, error)
}

type Number[T any] interface {
	Arithmetic() Arithmetic[T]

	AnnouncedLen() int
	TrueLen() uint

	algebra.WrappedElement[T]
}
