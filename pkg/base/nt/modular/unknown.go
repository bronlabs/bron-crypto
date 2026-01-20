package modular

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

// NewSimple constructs a SimpleModulus modular arithmetic instance
// from the given modulus m.
// Returns ct.False if the input is invalid (nil).
func NewSimple(m *numct.Modulus) (simple *SimpleModulus, ok ct.Bool) {
	return &SimpleModulus{m: m}, utils.BoolTo[ct.Bool](m != nil)
}

// SimpleModulus implements modular arithmetic modulo a single modulus m.
type SimpleModulus struct {
	m *numct.Modulus // The modulus
}

// MultiplicativeOrder returns an unknown cardinal for SimpleModulus.
func (*SimpleModulus) MultiplicativeOrder() algebra.Cardinal {
	return cardinal.Unknown()
}

// Modulus returns the modulus m.
func (m *SimpleModulus) Modulus() *numct.Modulus {
	return m.m
}

// ModMul computes out = (a * b) mod m.
func (m *SimpleModulus) ModMul(out, a, b *numct.Nat) {
	m.m.ModMul(out, a, b)
}

// ModExp computes out = (base ^ exp) mod m.
func (m *SimpleModulus) ModExp(out, base, exp *numct.Nat) {
	m.m.ModExp(out, base, exp)
}

// ModExpI computes out = (base ^ exp) mod m, where exp is a signed integer.
func (m *SimpleModulus) ModExpI(out, base *numct.Nat, exp *numct.Int) {
	m.m.ModExpI(out, base, exp)
}

// MultiBaseExp computes out[i] = (bases[i] ^ exp) mod m for all i.
func (m *SimpleModulus) MultiBaseExp(out, bases []*numct.Nat, exp *numct.Nat) {
	if len(out) != len(bases) {
		panic("out and bases must have the same length")
	}
	k := len(bases)

	var wg sync.WaitGroup
	wg.Add(k)
	for i := range k {
		go func(i int) {
			defer wg.Done()
			bi := bases[i]
			m.m.ModExp(out[i], bi, exp)
		}(i)
	}
	wg.Wait()
}

// ModInv computes out = (a^{-1}) mod m.
func (m *SimpleModulus) ModInv(out, a *numct.Nat) ct.Bool {
	return m.m.ModInv(out, a)
}

// ModDiv computes out = (a / b) mod m.
func (m *SimpleModulus) ModDiv(out, a, b *numct.Nat) ct.Bool {
	return m.m.ModDiv(out, a, b)
}

// Lift constructs a SimpleModulus modular arithmetic instance
// by lifting the modulus m to m^2.
// Returns ct.False if the lift operation fails.
func (m *SimpleModulus) Lift() (lifted *SimpleModulus, ok ct.Bool) {
	modulus := m.m.Nat()
	var m2 numct.Nat
	m2.Mul(modulus, modulus)
	m2Modulus, ok := numct.NewModulus(&m2)
	return &SimpleModulus{m: m2Modulus}, ok
}
