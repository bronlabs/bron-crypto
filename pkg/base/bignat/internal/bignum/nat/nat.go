//go:build !purego && !nobignum

package nat

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bignat/nat"
	"github.com/copperexchange/krypton-primitives/pkg/cgo/boring"
	"math/big"
)

type BnNatImpl boring.BigNum

var _ nat.Nat = (*BnNatImpl)(nil)

func (b *BnNatImpl) Clone() nat.Nat {
	n := (*boring.BigNum)(b)
	clone, err := n.Copy()
	if err != nil {
		panic(err)
	}

	return (*BnNatImpl)(clone)
}

func (b *BnNatImpl) Add(lhs, rhs nat.Nat, bits int) nat.Nat {
	n := (*boring.BigNum)(b)
	l := (*boring.BigNum)(lhs.(*BnNatImpl))
	r := (*boring.BigNum)(rhs.(*BnNatImpl))
	ret, err := n.Add(l, r)
	if err != nil {
		panic(err)
	}
	if bits >= 0 {
		ret, err = ret.MaskBits(uint(bits))
		if err != nil {
			panic(err)
		}
	}

	return (*BnNatImpl)(ret)
}

func (b *BnNatImpl) Sub(lhs, rhs nat.Nat, cap int) nat.Nat {
	n := (*boring.BigNum)(b)
	l := (*boring.BigNum)(lhs.(*BnNatImpl))
	r := (*boring.BigNum)(rhs.(*BnNatImpl))
	ret, err := n.Add(l, r)
	if err != nil {
		panic(err)
	}
	if cap >= 0 {
		ret, err = ret.MaskBits(uint(cap))
		if err != nil {
			panic(err)
		}
	}

	return (*BnNatImpl)(ret)
}

func (b *BnNatImpl) Mul(lhs, rhs nat.Nat, cap int) nat.Nat {
	n := (*boring.BigNum)(b)
	l := (*boring.BigNum)(lhs.(*BnNatImpl))
	r := (*boring.BigNum)(rhs.(*BnNatImpl))
	ctx := boring.NewBigNumCtx()

	ret, err := n.Mul(l, r, ctx)
	if err != nil {
		panic(err)
	}
	if cap >= 0 {
		ret, err = ret.MaskBits(uint(cap))
		if err != nil {
			panic(err)
		}
	}

	return (*BnNatImpl)(ret)
}

func (b *BnNatImpl) Div(lhs, rhs nat.Nat, cap int) nat.Nat {
	n := (*boring.BigNum)(b)
	l := (*boring.BigNum)(lhs.(*BnNatImpl))
	r := (*boring.BigNum)(rhs.(*BnNatImpl))
	ctx := boring.NewBigNumCtx()

	ret, err := n.Div(l, r, nil, ctx)
	if err != nil {
		panic(err)
	}
	if cap >= 0 {
		ret, err = ret.MaskBits(uint(cap))
		if err != nil {
			panic(err)
		}
	}

	return (*BnNatImpl)(ret)
}

func (b *BnNatImpl) Mod(x nat.Nat, m nat.Modulus) nat.Nat {
	r := (*boring.BigNum)(b)
	l := (*boring.BigNum)(x.(*BnNatImpl))
	bnMod := m.(*BnModImpl)
	mi := bnMod.BigNum
	bnCtx := boring.NewBigNumCtx()

	ret, err := r.Mod(l, mi, bnCtx)
	if err != nil {
		panic(err)
	}

	return (*BnNatImpl)(ret)
}

func (b *BnNatImpl) ModAdd(lhs, rhs nat.Nat, m nat.Modulus) nat.Nat {
	z := (*boring.BigNum)(b)
	l := (*boring.BigNum)(lhs.(*BnNatImpl))
	r := (*boring.BigNum)(rhs.(*BnNatImpl))
	bnMod := m.(*BnModImpl)
	mod := bnMod.BigNum

	ret, err := z.ModAdd(l, r, mod)
	if err != nil {
		panic(err)
	}

	return (*BnNatImpl)(ret)
}

func (b *BnNatImpl) ModInv(x nat.Nat, m nat.Modulus) nat.Nat {
	z := (*boring.BigNum)(b)
	l := (*boring.BigNum)(x.(*BnNatImpl))
	bnMod := m.(*BnModImpl)
	n := bnMod.BigNum
	bnCtx := boring.NewBigNumCtx()

	ret, err := z.ModInv(l, n, bnCtx)
	if err != nil {
		panic(err)
	}

	return (*BnNatImpl)(ret)
}

func (b *BnNatImpl) ModSub(lhs, rhs nat.Nat, m nat.Modulus) nat.Nat {
	z := (*boring.BigNum)(b)
	l := (*boring.BigNum)(lhs.(*BnNatImpl))
	r := (*boring.BigNum)(rhs.(*BnNatImpl))
	bnMod := m.(*BnModImpl)
	mod := bnMod.BigNum

	ret, err := z.ModSub(l, r, mod)
	if err != nil {
		panic(err)
	}

	return (*BnNatImpl)(ret)
}

func (b *BnNatImpl) ModMul(lhs, rhs nat.Nat, m nat.Modulus) nat.Nat {
	z := (*boring.BigNum)(b)
	l := (*boring.BigNum)(lhs.(*BnNatImpl))
	r := (*boring.BigNum)(rhs.(*BnNatImpl))
	bnMod := m.(*BnModImpl)
	mod := bnMod.BigNum
	bnCtx := boring.NewBigNumCtx()

	ret, err := z.ModMul(l, r, mod, bnCtx)
	if err != nil {
		panic(err)
	}

	return (*BnNatImpl)(ret)
}

func (b *BnNatImpl) ModExp(a, e nat.Nat, modulus nat.Modulus) nat.Nat {
	bi := (*boring.BigNum)(b)
	ai := (*boring.BigNum)(a.(*BnNatImpl))
	ei := (*boring.BigNum)(e.(*BnNatImpl))
	bnMod := modulus.(*BnModImpl)
	mi := bnMod.BigNum
	montCtx := bnMod.MontCtx
	ctx := boring.NewBigNumCtx()

	ret, err := bi.Exp(ai, ei, mi, montCtx, ctx)
	if err != nil {
		panic(err)
	}

	return (*BnNatImpl)(ret)
}

func (b *BnNatImpl) ModSqrt(x nat.Nat, m nat.Modulus) nat.Nat {
	z := (*boring.BigNum)(b)
	l := (*boring.BigNum)(x.(*BnNatImpl))
	bnMod := m.(*BnModImpl)
	n := bnMod.BigNum
	bnCtx := boring.NewBigNumCtx()

	ret, err := z.ModSqrt(l, n, bnCtx)
	if err != nil {
		panic(err)
	}

	return (*BnNatImpl)(ret)
}

func (b *BnNatImpl) Lsh(x nat.Nat, shift uint, cap int) nat.Nat {
	r := (*boring.BigNum)(b)
	xx := (*boring.BigNum)(x.(*BnNatImpl))

	ret, err := r.LShift(xx, int(shift))
	if err != nil {
		panic(err)
	}
	if cap >= 0 {
		ret, err = ret.MaskBits(uint(cap))
		if err != nil {
			panic(err)
		}
	}

	return (*BnNatImpl)(ret)
}

func (b *BnNatImpl) Rsh(x nat.Nat, shift uint, cap int) nat.Nat {
	r := (*boring.BigNum)(b)
	xx := (*boring.BigNum)(x.(*BnNatImpl))

	ret, err := r.RShift(xx, int(shift))
	if err != nil {
		panic(err)
	}
	if cap >= 0 {
		ret, err = ret.MaskBits(uint(cap))
		if err != nil {
			panic(err)
		}
	}

	return (*BnNatImpl)(ret)
}

func (b *BnNatImpl) Big() *big.Int {
	n := (*boring.BigNum)(b)
	bytes, err := n.Bytes()
	if err != nil {
		panic(err)
	}

	return new(big.Int).SetBytes(bytes)
}

func (b *BnNatImpl) Bytes() []byte {
	n := (*boring.BigNum)(b)
	bytes, err := n.Bytes()
	if err != nil {
		panic(err)
	}

	return bytes
}

func (b *BnNatImpl) AnnouncedLen() uint {
	n := (*boring.BigNum)(b)
	return n.WidthBits()
}

func (b *BnNatImpl) TrueLen() uint {
	n := (*boring.BigNum)(b)
	return n.NumBits()
}

func (b *BnNatImpl) Cmp(rhs nat.Nat) algebra.Ordering {
	bi := (*boring.BigNum)(b)
	ri := (*boring.BigNum)(rhs.(*BnNatImpl))
	r := bi.Cmp(ri)
	return algebra.Ordering(r)
}

func (b *BnNatImpl) Equal(rhs nat.Nat) bool {
	bi := (*boring.BigNum)(b)
	ri := (*boring.BigNum)(rhs.(*BnNatImpl))
	r := bi.Equal(ri)
	return r == 1
}

func (b *BnNatImpl) IsZero() bool {
	bi := (*boring.BigNum)(b)
	r := bi.IsZero()
	return r == 1
}
