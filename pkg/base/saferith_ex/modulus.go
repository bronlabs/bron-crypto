package saferith_ex

import "github.com/cronokirby/saferith"

type Modulus interface {
	Modulus() *saferith.Modulus
	Nat() *saferith.Nat
	Exp(base, exponent *saferith.Nat) *saferith.Nat
	MultiBaseExp(bases []*saferith.Nat, exponent *saferith.Nat) []*saferith.Nat
	MultiExponentExp(base *saferith.Nat, exponents []*saferith.Nat) []*saferith.Nat
}
