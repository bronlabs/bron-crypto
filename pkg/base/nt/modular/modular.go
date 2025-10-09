package modular

import (
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

type Arithmetic interface {
	Modulus() numct.Modulus
	ModExp(out, base, exp *numct.Nat)
	MultiBaseExp(out []*numct.Nat, bases []*numct.Nat, exp *numct.Nat)
	ModInv(out, a *numct.Nat) ct.Bool
}
