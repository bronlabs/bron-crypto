package modular

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

func NewSimple(m numct.Modulus) (*SimpleModulus, ct.Bool) {
	return &SimpleModulus{m: m}, utils.BoolTo[ct.Bool](m != nil)
}

type SimpleModulus struct {
	m numct.Modulus
}

func (u *SimpleModulus) MultiplicativeOrder() algebra.Cardinal {
	return cardinal.Unknown()
}

func (u *SimpleModulus) Modulus() numct.Modulus {
	return u.m
}

func (u *SimpleModulus) ModMul(out, a, b *numct.Nat) {
	u.m.ModMul(out, a, b)
}

func (u *SimpleModulus) ModExp(out, base, exp *numct.Nat) {
	u.m.ModExp(out, base, exp)
}

func (u *SimpleModulus) ModExpInt(out, base *numct.Nat, exp *numct.Int) {
	u.m.ModExpInt(out, base, exp)
}

func (u *SimpleModulus) MultiBaseExp(out []*numct.Nat, bases []*numct.Nat, exp *numct.Nat) {
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
			u.m.ModExp(out[i], bi, exp)
		}(i)
	}
	wg.Wait()
}

func (u *SimpleModulus) ModInv(out, a *numct.Nat) ct.Bool {
	return u.m.ModInv(out, a)
}

func (u *SimpleModulus) ModDiv(out, a, b *numct.Nat) ct.Bool {
	return u.m.ModDiv(out, a, b)
}

func (u *SimpleModulus) Lift() (*SimpleModulus, ct.Bool) {
	m := u.m.Nat()
	var m2 numct.Nat
	m2.Mul(m, m)
	var m2Modulus numct.Modulus
	var ok ct.Bool
	if m2.IsOdd() == ct.True {
		m2Modulus, ok = numct.NewModulusOdd(&m2)
	} else {
		m2Modulus, ok = numct.NewModulusNonZero(&m2)
	}
	return &SimpleModulus{m: m2Modulus}, ok
}
