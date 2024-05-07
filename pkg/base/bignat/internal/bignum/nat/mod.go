//go:build !purego && !nobignum

package nat

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/bignat/nat"
	"github.com/copperexchange/krypton-primitives/pkg/cgo/boring"
)

type BnModImpl struct {
	MontCtx *boring.BigNumMontCtx
	BigNum  *boring.BigNum
}

var _ nat.Modulus = (*BnModImpl)(nil)

func (b *BnModImpl) Nat() nat.Nat {
	return (*BnNatImpl)(b.BigNum)
}
