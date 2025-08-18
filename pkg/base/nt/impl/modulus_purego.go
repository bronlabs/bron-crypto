//go:build purego || nobignum

package impl

import "github.com/cronokirby/saferith"

func (m *ModulusOddPrime) ModExp(out, base, exp *Nat) {
	(*saferith.Nat)(out).Exp(
		(*saferith.Nat)(base),
		(*saferith.Nat)(exp),
		(*saferith.Modulus)(m),
	)
}

func (m *ModulusOddPrime) ModMul(out, x, y *Nat) {
	(*saferith.Nat)(out).ModMul(
		(*saferith.Nat)(x),
		(*saferith.Nat)(y),
		(*saferith.Modulus)(m),
	)
}
