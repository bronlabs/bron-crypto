package modular

import (
	"github.com/cronokirby/saferith"
)

type ResidueParams interface {
	GetModulus() *saferith.Modulus
	ModExp(base, exponent *saferith.Nat) (*saferith.Nat, error)
	ModMultiBaseExp(bases []*saferith.Nat, exponent *saferith.Nat) ([]*saferith.Nat, error)
}
