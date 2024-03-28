package bbot

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
)

var _ network.Message[ot.Protocol] = (*Round1P2P)(nil)
var _ network.Message[ot.Protocol] = (*Round2P2P)(nil)

type Round1P2P struct {
	MS curves.Point // mS ∈ Point
}
type Round2P2P struct {
	Phi [][2][]curves.Point // Φ ∈ [ξ][2][L]Point
}

func (r1p2p *Round1P2P) Validate(protocol ot.Protocol) error {
	if r1p2p.MS == nil {
		return errs.NewIsNil("mS")
	}
	if r1p2p.MS.IsIdentity() {
		return errs.NewIsIdentity("mS")
	}
	return nil
}

func (r2p2p *Round2P2P) Validate(protocol ot.Protocol) error {
	if len(r2p2p.Phi) == 0 {
		return errs.NewIsNil("phi")
	}
	if len(r2p2p.Phi) != protocol.Xi() {
		return errs.NewLength("len(phi)=%d is not Xi=%d", len(r2p2p.Phi), protocol.Xi())
	}
	for i := range protocol.Xi() {
		for j := range 2 {
			if len(r2p2p.Phi[i][j]) != protocol.L() {
				return errs.NewLength("len(phi[%d][%d])=%d is not L=%d", i, j, len(r2p2p.Phi[i][j]), protocol.L())
			}
			for k := range protocol.L() {
				if r2p2p.Phi[i][j][k] == nil {
					return errs.NewIsNil("phi[%d][%d][%d]", i, j, k)
				}
				if r2p2p.Phi[i][j][k].IsIdentity() {
					return errs.NewIsIdentity("phi[%d][%d][%d]", i, j, k)
				}
			}
		}
	}
	return nil
}
