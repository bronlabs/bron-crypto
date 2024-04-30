//go:build !purego && !nobignum

package bignum

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/nat"
	"github.com/copperexchange/krypton-primitives/pkg/cgo/boring"
)

type BnMod struct {
	montCtx *boring.BigNumMontCtx
	bigNum  *boring.BigNum
}

var _ nat.Modulus = (*BnMod)(nil)

func (b *BnMod) Nat() nat.Nat {
	return (*BnNat)(b.bigNum)
}
