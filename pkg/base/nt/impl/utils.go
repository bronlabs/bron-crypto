package impl

import (
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
	"github.com/cronokirby/saferith"
)

// n must already be reduced mod p^k
func Vp[MF internal.ModulusMutablePtr[N, MFT], N internal.NatMutablePtr[N, NT], MFT, NT any](out N, p MF, n N, k int) int {
	var temp NT
	N(&temp).Set(n)

	var quo, rem NT
	m := 0
	for range k {
		p.Mod(N(&rem), N(&temp))
		isDiv := N(&rem).IsZero()
		p.ModDiv(N(&quo), N(&temp), p.Nat())             // TODO: add Quo method
		N(&temp).CondAssign(isDiv, N(&temp), N(&quo)) // if divisible → take quo
		m += int(isDiv)
	}
	out.Set(N(&temp)) // u := a / p^m mod p^k
	return m
}

// LegendreSymbol computes (x|p) via Euler's criterion in constant time w.r.t. x.
// p must be an odd prime. Returns -1, 0, or +1.
func LegendreSymbol[M internal.ModulusMutable[*Nat]](m M, x *Nat) int8 {
	p := saferith.ModulusFromNat((*saferith.Nat)(m.Nat()))

	// xr = x mod p
	xr := new(saferith.Nat).Mod((*saferith.Nat)(x), p)

	// e = (p-1)/2   (depends only on public modulus)
	pm1 := new(saferith.Nat).Sub(p.Nat(), new(saferith.Nat).SetUint64(1), p.BitLen())
	e := new(saferith.Nat).Rsh(pm1, 1, -1)

	// t = xr^e mod p  (saferith.Exp is CT w.r.t. base for odd moduli)
	t := new(saferith.Nat).Exp(xr, e, p)

	// Compare t to {0,1} without branches
	one := new(saferith.Nat).SetUint64(1)
	one.Resize(p.BitLen())
	eq1 := t.Eq(one)  // saferith.Choice (0 or 1)
	eq0 := t.EqZero() // saferith.Choice (0 or 1)

	// Map (eq0,eq1) -> {-1,0,1} in constant time:
	//  t==0: (1,0) ->  0
	//  t==1: (0,1) -> +1
	//  else: (0,0) -> -1
	a := uint8(eq1)
	b := uint8(eq0)
	return int8(a) - int8(1-(b+a))
}

// HasSqrt returns 1 iff x has a square root mod p (including x≡0), in CT w.r.t. x.
func HasSqrt(m *ModulusOddPrime, x *Nat) ct.Bool {
	p := (*saferith.Modulus)(m)

	// xr = x mod p
	xr := new(saferith.Nat).Mod((*saferith.Nat)(x), p)

	// e = (p-1)/2
	pm1 := new(saferith.Nat).Sub(p.Nat(), new(saferith.Nat).SetUint64(1), p.BitLen())
	e := new(saferith.Nat).Rsh(pm1, 1, -1)

	// t = xr^e mod p
	t := new(saferith.Nat).Exp(xr, e, p)

	one := new(saferith.Nat).SetUint64(1)
	one.Resize(p.BitLen())

	isResidue := ct.Bool(t.Eq(one)) // Legendre == 1
	isZero := ct.Bool(t.EqZero())   // x ≡ 0 ⇒ t == 0
	return isResidue | isZero
}
