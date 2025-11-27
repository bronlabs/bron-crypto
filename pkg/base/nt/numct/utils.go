package numct

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
)

var ErrInvalidArgument = errs2.New("invalid argument")

// Vp computes the p-adic valuation of n with respect to p and precision k.
// n must already be reduced mod p^k.
func Vp(out *Nat, p *Modulus, n *Nat, k int) int {
	temp := n.Clone()
	var quo, rem Nat
	m := 0
	for range k {
		p.Mod(&rem, temp)
		isDiv := rem.IsZero()
		p.Quo(&quo, temp)
		temp.Select(isDiv, temp, &quo)
		m += int(isDiv)
	}
	out.Set(temp) // u := a / p^m mod p^k
	return m
}
