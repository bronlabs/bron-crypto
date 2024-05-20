package integer

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
)

type Arithmetic[T any] interface {
	New(v uint64) T
	Cmp(x, y T) algebra.Ordering
	IsEven(x T) bool
	IsProbablyPrime(x T) bool

	Neg(x T) (T, error)
	Add(x, y T) (T, error)
	Sub(x, y T) (T, error)
	Mul(x, y T) (T, error)
	Div(x, y T) (quotient, remainder T, err error)
	Mod(x, m T) (T, error)

	Sqrt(x T) (T, error)

	Exp(x, y T) (T, error)
	SimExp(bases, exponents []T) (T, error)
	MultiBaseExp(bases []T, exponent T) (T, error)
	MultiExponentExp(base T, exponents []T) (T, error)

	Uint64(x T) uint64
}

// type SignedArithmetic[T any] interface {
// 	Arithmetic[T]

// 	NewSignedArithmetic(validate bool) SignedArithmetic[T]
// }

// type UnsignedPositiveArithmetic[T any] interface {
// 	Arithmetic[T]

// 	NewUnsignedPositiveArithmetic(validate bool) UnsignedPositiveArithmetic[T]
// }

// type UnsignedArithmetic[T any] interface {
// 	Arithmetic[T]

// 	NewUnsignedArithmetic(validate bool) UnsignedArithmetic[T]
// }

type ModularArithmetic[T any] interface {
	Arithmetic[T]

	Inverse(x T) (T, error)

	// NewModularArithmetic(modulus T, validate bool) (ModularArithmetic[T], error)
	// NewPrimesPowerModularArithmetic(primes []T, powers []uint, validate bool) (ModularArithmetic[T], error)
}

type Number[T any] interface {
	Arithmetic() Arithmetic[T]

	AnnouncedLen() int
	TrueLen() uint

	algebra.WrappedElement[T]
	algebra.NatLike[T]
}
