package nat

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"math/big"
)

type Nat interface {
	Clone() Nat

	Add(lhs, rhs Nat, cap int) Nat
	Sub(lhs, rhs Nat, cap int) Nat
	Mul(lhs, rhs Nat, cap int) Nat
	Div(lhs, rhs Nat, cap int) Nat

	Mod(x Nat, m Modulus) Nat
	ModAdd(lhs, rhs Nat, m Modulus) Nat
	ModSub(lhs, rhs Nat, m Modulus) Nat
	ModMul(lhs, rhs Nat, m Modulus) Nat
	ModInv(x Nat, m Modulus) Nat
	ModSqrt(x Nat, m Modulus) Nat
	ModExp(a, e Nat, modulus Modulus) Nat

	Lsh(x Nat, shift uint, cap int) Nat
	Rsh(x Nat, shift uint, cap int) Nat

	Big() *big.Int
	AnnouncedLen() uint
	TrueLen() uint
	Bytes() []byte

	Cmp(rhs Nat) algebra.Ordering
	Equal(rhs Nat) bool
	IsZero() bool

	// TODO: Add remaining methods
}

type Modulus interface {
	Nat() Nat
}
