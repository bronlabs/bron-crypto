package saferith

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/nat"
	"github.com/cronokirby/saferith"
	"math/big"
)

type SNat saferith.Nat

var _ nat.Nat = (*SNat)(nil)

func (s *SNat) Add(lhs, rhs nat.Nat, bits int) nat.Nat {
	n := (*saferith.Nat)(s)
	l := (*saferith.Nat)(lhs.(*SNat))
	r := (*saferith.Nat)(rhs.(*SNat))
	return (*SNat)(n.Add(l, r, bits))
}

func (s *SNat) AnnouncedLen() uint {
	n := (*saferith.Nat)(s)
	return uint(n.AnnouncedLen())
}

func (s *SNat) Big() *big.Int {
	n := (*saferith.Nat)(s)
	return n.Big()
}

func (s *SNat) Clone() nat.Nat {
	n := (*saferith.Nat)(s)
	return (*SNat)(n.Clone())
}

func (s *SNat) ExpMod(a, e nat.Nat, modulus nat.Modulus) nat.Nat {
	si := (*saferith.Nat)(s)
	ai := (*saferith.Nat)(a.(*SNat))
	ei := (*saferith.Nat)(e.(*SNat))
	mi := (*saferith.Modulus)(modulus.(*SMod))
	return (*SNat)(si.Exp(ai, ei, mi))
}

func (s *SNat) Cmp(rhs nat.Nat) algebra.Ordering {
	si := (*saferith.Nat)(s)
	ri := (*saferith.Nat)(rhs.(*SNat))
	g, _, l := si.Cmp(ri)
	return algebra.Ordering(g - l)
}
