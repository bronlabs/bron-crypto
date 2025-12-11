package modular

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

// Arithmetic defines modular arithmetic operations over a modulus.
// Implementations may use CRT or other optimizations as appropriate.
type Arithmetic interface {
	// Modulus returns the modulus used in the modular arithmetic.
	Modulus() *numct.Modulus
	// MultiplicativeOrder returns the multiplicative order of the modulus.
	MultiplicativeOrder() algebra.Cardinal
	// ModMul computes out = (a * b) mod m.
	ModMul(out, a, b *numct.Nat)
	// ModDiv computes out = (a / b) mod m.
	ModDiv(out, a, b *numct.Nat) ct.Bool
	// ModExp computes out = (base ^ exp) mod m.
	ModExp(out, base, exp *numct.Nat)
	// ModExpI computes out = (base ^ exp) mod m, where exp is a signed integer.
	ModExpI(out, base *numct.Nat, exp *numct.Int)
	// MultiBaseExp computes out[i] = (bases[i] ^ exp) mod m for all i.
	MultiBaseExp(out []*numct.Nat, bases []*numct.Nat, exp *numct.Nat)
	// ModInv computes out = (a^{-1}) mod m.
	ModInv(out, a *numct.Nat) ct.Bool
}
