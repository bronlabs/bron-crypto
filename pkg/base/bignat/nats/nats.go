package nats

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/bignat/nat"
	"io"
	"math/big"
)

type Nats interface {
	Zero() nat.Nat
	One() nat.Nat

	New() nat.Nat
	NewBig(b *big.Int) nat.Nat
	NewUint64(val uint64) nat.Nat
	NewRandomN(n nat.Nat, prng io.Reader) nat.Nat
	NewRandomBits(n uint, prng io.Reader) nat.Nat
	NewPrime(bits uint, prng io.Reader) nat.Nat
	NewSafePrime(bits uint, prng io.Reader) nat.Nat
	NewFromBytes(bytes []byte) nat.Nat
	NewModulus(modulus nat.Nat) nat.Modulus
}
