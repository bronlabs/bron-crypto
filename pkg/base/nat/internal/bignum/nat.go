//go:build !purego && !nobignum

package bignum

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/nat"
	"github.com/copperexchange/krypton-primitives/pkg/cgo/boring"
	"math/big"
)

type BnNat boring.BigNum

var _ nat.Nat = (*BnNat)(nil)

func (b *BnNat) Add(lhs, rhs nat.Nat, bits int) nat.Nat {
	n := (*boring.BigNum)(b)
	l := (*boring.BigNum)(lhs.(*BnNat))
	r := (*boring.BigNum)(rhs.(*BnNat))
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

	return (*BnNat)(ret)
}

func (b *BnNat) Big() *big.Int {
	n := (*boring.BigNum)(b)
	bytes, err := n.Bytes()
	if err != nil {
		panic(err)
	}

	return new(big.Int).SetBytes(bytes)
}

func (b *BnNat) AnnouncedLen() uint {
	n := (*boring.BigNum)(b)
	return n.AnnouncedLen()
}

func (b *BnNat) Clone() nat.Nat {
	n := (*boring.BigNum)(b)
	clone, err := n.Copy()
	if err != nil {
		panic(err)
	}

	return (*BnNat)(clone)
}

func (b *BnNat) ExpMod(a, e nat.Nat, modulus nat.Modulus) nat.Nat {
	bi := (*boring.BigNum)(b)
	ai := (*boring.BigNum)(a.(*BnNat))
	ei := (*boring.BigNum)(e.(*BnNat))
	bnMod := modulus.(*BnMod)
	mi := bnMod.bigNum
	montCtx := bnMod.montCtx
	ctx := boring.NewBigNumCtx()

	ret, err := bi.Exp(ai, ei, mi, montCtx, ctx)
	if err != nil {
		panic(err)
	}

	return (*BnNat)(ret)
}

func (b *BnNat) Cmp(rhs nat.Nat) algebra.Ordering {
	bi := (*boring.BigNum)(b)
	ri := (*boring.BigNum)(rhs.(*BnNat))
	r := bi.Cmp(ri)
	return algebra.Ordering(r)
}
