package integer

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
)

type Arithmetic[T any] interface {
	Name() string

	Equal(x, y T) bool
	Cmp(x, y T) algebra.Ordering

	Zero() T
	One() T
	Two() T

	IsEven(x T) bool
	IsOdd(x T) bool

	Abs(x T) T
	Neg(x T) (T, error)

	IsCoPrime(x, y T) (bool, error)
	GCD(x, y T) (T, error)
	LCM(x, y T) (T, error)
	Sqrt(x T) (T, error)

	Uint64(x T) uint64

	Inverse(x T) (T, error)
	Add(x, y T) (T, error)
	Sub(x, y T) (T, error)
	Mul(x, y T) (T, error)
	Exp(x, y T) (T, error)
	Div(x, y T) (quotient, remainder T, err error)

	Mod(x, m T) (T, error)
}

type SignedArithmetic[T any] interface {
	Arithmetic[T]

	NewSignedArithmetic(validate bool) SignedArithmetic[T]
}

type UnsignedPositiveArithmetic[T any] interface {
	Arithmetic[T]

	NewUnsignedPositiveArithmetic(validate bool) UnsignedPositiveArithmetic[T]
}

type UnsignedArithmetic[T any] interface {
	Arithmetic[T]

	NewUnsignedArithmetic(validate bool) UnsignedArithmetic[T]
}

type ModularArithmetic[T any] interface {
	Arithmetic[T]

	NewModularArithmetic(modulus T, validate bool) (ModularArithmetic[T], error)
	NewPrimesPowerModularArithmetic(primes []T, powers []uint, validate bool) (ModularArithmetic[T], error)
	NewOddModulusModularArithmetic(oddModulus T, validate bool) (ModularArithmetic[T], error)
}

// type Number[T any] interface {
// 	Arithmetic() Arithmetic[T]

// 	AnnouncedLen() int
// 	TrueLen() uint

// 	algebra.WrappedElement[T]
// 	algebra.NatLike[T]
// }
