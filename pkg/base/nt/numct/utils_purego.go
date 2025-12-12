//go:build purego || nobignum

package numct

import "github.com/bronlabs/bron-crypto/pkg/base/ct"

func LCM(out, a, b *Nat) {
	if a.IsZero()|b.IsZero() == ct.True {
		out.SetZero()
		return
	}
	// LCM(a, b) = (a * b) / GCD(a, b)
	var gcd, ab Nat
	gcd.GCD(a, b)
	ab.Mul(a, b)
	denom, _ := NewModulus(&gcd)
	out.EuclideanDivVarTime(&ab, denom, -1)
}
