package internal

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

type modulusMutable[N NatMutable[N]] interface {
	Nat() N
	SetNat(N) ct.Bool

	InRange(x N) ct.Bool
	IsUnit(x N) ct.Bool

	Mod(out, x N)
	Quo(out, x N) // out = floor(x / m)  (Euclidean integer division)
	QuoCap(out, x N, cap algebra.Capacity)

	ModAdd(out, x, y N)
	ModSub(out, x, y N)
	ModMul(out, x, y N)
	ModDiv(out, x, y N) ct.Bool
	ModInv(out, x N) ct.Bool
	ModNeg(out, x N)
	ModExp(out, base, exp N)
	ModSqrt(out, x N) ct.Bool

	BitLen() uint
	base.BytesLike
	fmt.Stringer
}

type ModulusMutable[N NatMutable[N]] modulusMutable[N]

type ModulusMutablePtr[N NatMutable[N], MT any] interface {
	*MT
	ModulusMutable[N]
	Set(*MT)
}

type natMutable[E aimpl.MonoidElement[E]] interface {
	aimpl.MonoidElement[E]
	ct.Comparable[E]
	base.Clonable[E]
	IsOne() ct.Bool
	SetOne()

	AddCap(lhs, rhs E, cap algebra.Capacity)
	SubCap(lhs, rhs E, cap algebra.Capacity)

	Mul(lhs, rhs E)
	MulCap(lhs, rhs E, cap algebra.Capacity)

	DivCap(lhs, rhs E, cap algebra.Capacity) (ok ct.Bool)
	Mod(a, m E) (ok ct.Bool)
	DivModCap(outQuot, outRem, lhs, rhs E, cap algebra.Capacity) (ok ct.Bool)

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
	fmt.Stringer
}

type NatMutable[E natMutable[E]] natMutable[E]

type NatMutablePtr[E NatMutable[E], T any] interface {
	*T
	NatMutable[E]
}

type intMutable[E aimpl.RingElement[E]] interface {
	aimpl.RingElement[E]
	natMutable[E]
	Int64() int64
	SetInt64(x int64)
	IsNegative() ct.Bool
}

type IntMutable[E intMutable[E]] intMutable[E]

type IntMutablePtr[E IntMutable[E], T any] interface {
	*T
	IntMutable[E]
}
