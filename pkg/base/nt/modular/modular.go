package modular

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

type Arithmetic interface {
	Modulus() numct.Modulus
	MultiplicativeOrder() algebra.Cardinal
	ModMul(out, a, b *numct.Nat)
	ModDiv(out, a, b *numct.Nat) ct.Bool
	ModExp(out, base, exp *numct.Nat)
	ModExpInt(out, base *numct.Nat, exp *numct.Int)
	MultiBaseExp(out []*numct.Nat, bases []*numct.Nat, exp *numct.Nat)
	ModInv(out, a *numct.Nat) ct.Bool
}
