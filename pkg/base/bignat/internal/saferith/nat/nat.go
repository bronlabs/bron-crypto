package nat

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bignat/nat"
	"github.com/cronokirby/saferith"
	"math/big"
)

type SnatImpl saferith.Nat

var _ nat.Nat = (*SnatImpl)(nil)

func (s *SnatImpl) Clone() nat.Nat {
	n := (*saferith.Nat)(s)
	return (*SnatImpl)(n.Clone())
}

func (s *SnatImpl) Add(lhs, rhs nat.Nat, bits int) nat.Nat {
	n := (*saferith.Nat)(s)
	l := (*saferith.Nat)(lhs.(*SnatImpl))
	r := (*saferith.Nat)(rhs.(*SnatImpl))
	return (*SnatImpl)(n.Add(l, r, bits))
}

func (s *SnatImpl) Sub(lhs, rhs nat.Nat, bits int) nat.Nat {
	n := (*saferith.Nat)(s)
	l := (*saferith.Nat)(lhs.(*SnatImpl))
	r := (*saferith.Nat)(rhs.(*SnatImpl))
	return (*SnatImpl)(n.Sub(l, r, bits))
}

func (s *SnatImpl) Mul(lhs, rhs nat.Nat, bits int) nat.Nat {
	n := (*saferith.Nat)(s)
	l := (*saferith.Nat)(lhs.(*SnatImpl))
	r := (*saferith.Nat)(rhs.(*SnatImpl))
	return (*SnatImpl)(n.Mul(l, r, bits))
}

func (s *SnatImpl) Div(lhs, rhs nat.Nat, bits int) nat.Nat {
	n := (*saferith.Nat)(s)
	l := (*saferith.Nat)(lhs.(*SnatImpl))
	r := (*saferith.Nat)(rhs.(*SnatImpl))
	return (*SnatImpl)(n.Div(l, saferith.ModulusFromNat(r), bits))
}

func (s *SnatImpl) Mod(x nat.Nat, m nat.Modulus) nat.Nat {
	ss := (*saferith.Nat)(s)
	xx := (*saferith.Nat)(x.(*SnatImpl))
	mm := (*saferith.Modulus)(m.(*SmodImpl))
	return (*SnatImpl)(ss.Mod(xx, mm))
}

func (s *SnatImpl) ModAdd(lhs nat.Nat, rhs nat.Nat, m nat.Modulus) nat.Nat {
	n := (*saferith.Nat)(s)
	l := (*saferith.Nat)(lhs.(*SnatImpl))
	r := (*saferith.Nat)(rhs.(*SnatImpl))
	mm := (*saferith.Modulus)(m.(*SmodImpl))
	return (*SnatImpl)(n.ModAdd(l, r, mm))
}

func (s *SnatImpl) ModSub(lhs nat.Nat, rhs nat.Nat, m nat.Modulus) nat.Nat {
	n := (*saferith.Nat)(s)
	l := (*saferith.Nat)(lhs.(*SnatImpl))
	r := (*saferith.Nat)(rhs.(*SnatImpl))
	mm := (*saferith.Modulus)(m.(*SmodImpl))
	return (*SnatImpl)(n.ModSub(l, r, mm))
}

func (s *SnatImpl) ModMul(lhs nat.Nat, rhs nat.Nat, m nat.Modulus) nat.Nat {
	n := (*saferith.Nat)(s)
	l := (*saferith.Nat)(lhs.(*SnatImpl))
	r := (*saferith.Nat)(rhs.(*SnatImpl))
	mm := (*saferith.Modulus)(m.(*SmodImpl))
	return (*SnatImpl)(n.ModMul(l, r, mm))
}

func (s *SnatImpl) ModInv(x nat.Nat, m nat.Modulus) nat.Nat {
	ss := (*saferith.Nat)(s)
	xx := (*saferith.Nat)(x.(*SnatImpl))
	mm := (*saferith.Modulus)(m.(*SmodImpl))
	return (*SnatImpl)(ss.Mod(xx, mm))
}

func (s *SnatImpl) ModSqrt(x nat.Nat, m nat.Modulus) nat.Nat {
	ss := (*saferith.Nat)(s)
	xx := (*saferith.Nat)(x.(*SnatImpl))
	mm := (*saferith.Modulus)(m.(*SmodImpl))
	return (*SnatImpl)(ss.ModSqrt(xx, mm))
}

func (s *SnatImpl) ModExp(a, e nat.Nat, modulus nat.Modulus) nat.Nat {
	si := (*saferith.Nat)(s)
	ai := (*saferith.Nat)(a.(*SnatImpl))
	ei := (*saferith.Nat)(e.(*SnatImpl))
	mi := (*saferith.Modulus)(modulus.(*SmodImpl))
	return (*SnatImpl)(si.Exp(ai, ei, mi))
}

func (s *SnatImpl) Lsh(x nat.Nat, shift uint, cap int) nat.Nat {
	ss := (*saferith.Nat)(s)
	xx := (*saferith.Nat)(x.(*SnatImpl))
	return (*SnatImpl)(ss.Lsh(xx, shift, cap))
}

func (s *SnatImpl) Rsh(x nat.Nat, shift uint, cap int) nat.Nat {
	ss := (*saferith.Nat)(s)
	xx := (*saferith.Nat)(x.(*SnatImpl))
	return (*SnatImpl)(ss.Rsh(xx, shift, cap))
}

func (s *SnatImpl) AnnouncedLen() uint {
	n := (*saferith.Nat)(s)
	return uint(n.AnnouncedLen())
}

func (s *SnatImpl) TrueLen() uint {
	n := (*saferith.Nat)(s)
	return uint(n.TrueLen())
}

func (s *SnatImpl) Bytes() []byte {
	n := (*saferith.Nat)(s)
	return n.Bytes()
}

func (s *SnatImpl) Big() *big.Int {
	n := (*saferith.Nat)(s)
	return n.Big()
}

func (s *SnatImpl) Cmp(rhs nat.Nat) algebra.Ordering {
	si := (*saferith.Nat)(s)
	ri := (*saferith.Nat)(rhs.(*SnatImpl))
	g, _, l := si.Cmp(ri)
	return algebra.Ordering(g - l)
}

func (s *SnatImpl) Equal(rhs nat.Nat) bool {
	l := (*saferith.Nat)(s)
	r := (*saferith.Nat)(rhs.(*SnatImpl))
	return l.Eq(r) == 1
}

func (s *SnatImpl) IsZero() bool {
	l := (*saferith.Nat)(s)
	return l.EqZero() == 1
}
