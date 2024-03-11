package bbot

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/network"
)

var _ network.MessageLike = (*Round1P2P)(nil)
var _ network.MessageLike = (*Round2P2P)(nil)

type Round1P2P struct {
	MS curves.Point // mS ∈ Point
}
type Round2P2P struct {
	Phi [][2][]curves.Point // Φ ∈ [ξ][2][L]Point
}

func (r1p2p *Round1P2P) Validate(none ...int) error {
	if r1p2p.MS == nil {
		return errs.NewIsNil("mS")
	}
	return nil
}

func (r2p2p *Round2P2P) Validate(L_Xi ...int) error {
	L, Xi := L_Xi[0], L_Xi[1]
	if len(r2p2p.Phi) == 0 {
		return errs.NewIsNil("phi")
	}
	if len(r2p2p.Phi) != Xi {
		return errs.NewLength("len(phi)=%d is not Xi=%d", len(r2p2p.Phi), Xi)
	}
	for i := 0; i < Xi; i++ {
		for j := 0; j < 2; j++ {
			if len(r2p2p.Phi[i][j]) != L {
				return errs.NewLength("len(phi[%d][%d])=%d is not L=%d", i, j, len(r2p2p.Phi[i][j]), L)
			}
		}
	}
	return nil
}
