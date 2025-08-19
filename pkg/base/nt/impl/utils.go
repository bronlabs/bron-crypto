package impl

import (
	"github.com/bronlabs/bron-crypto/pkg/base/nt/internal"
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
		p.Quo(N(&quo), N(&temp))                      // exact division by p
		N(&temp).CondAssign(isDiv, N(&temp), N(&quo)) // if divisible → take quo
		m += int(isDiv)
	}
	out.Set(N(&temp)) // u := a / p^m mod p^k
	return m
}
