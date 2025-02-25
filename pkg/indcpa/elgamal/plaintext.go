package elgamal

import (
	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

type Plaintext2048 struct {
	V *saferith.Nat
}

func NewPlaintext2048FromNat(v *saferith.Nat) (*Plaintext2048, error) {
	neqZero := v.EqZero() ^ 1
	_, eqQ, ltQ := v.CmpMod(Ffdhe2048Order)
	ok := neqZero & (eqQ | ltQ)
	el := new(saferith.Nat).ModMul(v, v, Ffdhe2048Modulus)

	if ok != 1 {
		return nil, errs.NewFailed("invalid plaintext")
	} else {
		return &Plaintext2048{V: el}, nil
	}
}

func (p *Plaintext2048) ToNat() *saferith.Nat {
	v := new(saferith.Nat).ModSqrt(p.V, Ffdhe2048Modulus)
	vNeg := new(saferith.Nat).ModNeg(v, Ffdhe2048Modulus)
	_, e, l := v.CmpMod(Ffdhe2048Order)
	n := new(saferith.Nat)
	n.CondAssign(e|l, v)
	n.CondAssign((e|l)^1, vNeg)

	return n
}
