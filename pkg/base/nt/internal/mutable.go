package internal

import (
	"fmt"
	"io"
	"math/big"

	"github.com/cronokirby/saferith"
	"github.com/fxamacker/cbor/v2"

	"github.com/bronlabs/bron-crypto/pkg/base"
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
)

// TODO: change ModI -> ModI
type modulusMutable[I, N any] interface {
	Nat() N
	SetNat(N) ct.Bool

	IsInRange(x N) ct.Bool
	IsInRangeSymmetric(x I) ct.Bool
	IsUnit(x N) ct.Bool

	Mod(out, x N)
	ModI(out N, x I)
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
	ModExpI(out, base N, exp I)

	Random(io.Reader) (N, error)
	BitLen() int
	HashCode() base.HashCode
	Big() *big.Int
	Saferith() *saferith.Modulus
	base.BytesLike
	cbor.Marshaler
	cbor.Unmarshaler
	fmt.Stringer
}

type ModulusMutable[I IntMutable[I, MI], N NatMutable[N, MI], MI any] modulusMutable[I, N]

type ModulusMutablePtr[I IntMutable[I, MI], N NatMutable[N, MI], MI, MT any] interface {
	*MT
	ModulusMutable[I, N, MI]
	Set(*MT)
}

// TODO: add fill bytes
// TODO: set bit
type natMutable[E aimpl.MonoidElementLowLevel[E], M any] interface {
	aimpl.MonoidElementLowLevel[E]
	ct.Comparable[E]
	base.Clonable[E]
	IsOne() ct.Bool
	SetOne()

	AddCap(lhs, rhs E, cap int)
	SubCap(lhs, rhs E, cap int)

	Mul(lhs, rhs E)
	MulCap(lhs, rhs E, cap int)

	DivModCap(numerator E, denominator M, cap int) (ok ct.Bool)
	ExactDivMod(numerator E, denominator M) (ok ct.Bool)

	Increment()
	Decrement()

	Bit(i uint) byte

	TrueLen() int
	AnnouncedLen() int
	IsProbablyPrime() ct.Bool

	Coprime(x E) ct.Bool

	Resize(cap int)

	Rsh(x E, shift uint)
	RshCap(x E, shift uint, cap int)

	Lsh(x E, shift uint)
	LshCap(x E, shift uint, cap int)

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

type intMutable[E aimpl.RingElementLowLevel[E], M any] interface {
	aimpl.RingElementLowLevel[E]
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
