package recovery

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/hjky"
)

var _ network.Message = (*Round2P2P)(nil)

type Round1Broadcast = hjky.Round1Broadcast
type Round1P2P = hjky.Round1P2P

type Round2P2P struct {
	BlindedPartiallyRecoveredShare curves.Scalar

	_ ds.Incomparable
}

func (r2p2p *Round2P2P) Validate(none ...int) error {
	if r2p2p.BlindedPartiallyRecoveredShare == nil {
		return errs.NewIsNil("blinded partially recovered share")
	}
	return nil
}
