package internal

import (
	"fmt"
	"io"
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/cronokirby/saferith"
)

type modulusMutable[I, N any] interface {
	Nat() N
	SetNat(N) ct.Bool

	IsInRange(x N) ct.Bool
	IsInRangeSymmetric(x I) ct.Bool
	IsUnit(x N) ct.Bool

	Mod(out, x N)
	ModInt(out N, x I)
	ModSymmetric(out I, x N)

	Quo(out, x N) // out = floor(x / m)  (Euclidean integer division)

	ModAdd(out, x, y N)
	ModSub(out, x, y N)
	ModMul(out, x, y N)
	ModDiv(out, x, y N) ct.Bool
	ModInv(out, x N) ct.Bool
	ModNeg(out, x N)
	ModSqrt(out, x N) ct.Bool

	ModExp(out, base, exp N)
	ModMultiBaseExp(out []N, bases []N, exp N)
	ModExpInt(out, base N, exp I)

	Random(io.Reader) (N, error)
	BitLen() uint
	HashCode() base.HashCode
	Big() *big.Int
	Saferith() *saferith.Modulus
	base.BytesLike
	fmt.Stringer
}

type ModulusMutable[I IntMutable[I, MI], N NatMutable[N, MI], MI any] modulusMutable[I, N]

type ModulusMutablePtr[I IntMutable[I, MI], N NatMutable[N, MI], MI, MT any] interface {
	*MT
	ModulusMutable[I, N, MI]
	Set(*MT)
}

type natMutable[E aimpl.MonoidElement[E], M any] interface {
	aimpl.MonoidElement[E]
	ct.Comparable[E]
	base.Clonable[E]
	IsOne() ct.Bool
	SetOne()

	AddCap(lhs, rhs E, cap algebra.Capacity)
	SubCap(lhs, rhs E, cap algebra.Capacity)

	Mul(lhs, rhs E)
	MulCap(lhs, rhs E, cap algebra.Capacity)

	DivCap(numerator E, denominator M, cap algebra.Capacity) (ok ct.Bool)
	ExactDiv(numerator E, denominator M) (ok ct.Bool)

	Increment()
	Decrement()

	Bit(i uint) byte

	TrueLen() uint
	AnnouncedLen() uint
	IsProbablyPrime() ct.Bool

	Coprime(x E) ct.Bool

	Resize(cap algebra.Capacity)

	Rsh(x E, shift uint)
	RshCap(x E, shift uint, cap algebra.Capacity)

	Lsh(x E, shift uint)
	LshCap(x E, shift uint, cap algebra.Capacity)

	IsOdd() ct.Bool
	IsEven() ct.Bool

	Uint64() uint64
	SetUint64(x uint64)
	HashCode() base.HashCode
	Big() *big.Int
	fmt.Stringer
}

type NatMutable[E natMutable[E, M], M any] natMutable[E, M]

type NatMutablePtr[E NatMutable[E, M], M, T any] interface {
	*T
	NatMutable[E, M]
}

type intMutable[E aimpl.RingElement[E], M any] interface {
	aimpl.RingElement[E]
	natMutable[E, M]
	Int64() int64
	SetInt64(x int64)
	IsNegative() ct.Bool
}

type IntMutable[E intMutable[E, M], M any] intMutable[E, M]

type IntMutablePtr[E IntMutable[E, M], M, T any] interface {
	*T
	IntMutable[E, M]
}
