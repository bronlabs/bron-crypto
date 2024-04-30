package nat

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"io"
	"math/big"
)

type Nats interface {
	New() Nat
	Zero() Nat
	One() Nat
	NewUint64(val uint64) Nat
	NewRandomN(n Nat, prng io.Reader) Nat
	NewRandomBits(n uint, prng io.Reader) Nat
	NewPrime(bits uint, prng io.Reader) Nat
	NewSafePrime(bits uint, prng io.Reader) Nat
	NewFromBytes(bytes []byte) Nat
	NewModulus(modulus Nat) Modulus
}

type Nat interface {
	Add(lhs, rhs Nat, bits int) Nat
	Big() *big.Int
	AnnouncedLen() uint
	Clone() Nat
	ExpMod(a, e Nat, modulus Modulus) Nat
	Cmp(rhs Nat) algebra.Ordering
	// TODO: Add remaining methods
}

type Modulus interface {
	Nat() Nat
}
