package refresh

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils/safecast"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/hjky"
)

var _ network.Message[types.ThresholdProtocol] = (*Round1Broadcast)(nil)

type Round1Broadcast struct {
	Sampler                   *hjky.Round1Broadcast
	PreviousFeldmanCommitment []curves.Point

	_ ds.Incomparable
}

type Round1P2P = hjky.Round1P2P

func (r1b *Round1Broadcast) Validate(protocol types.ThresholdProtocol) error {
	if r1b.Sampler == nil {
		return errs.NewIsNil("sampler")
	}
	if len(r1b.PreviousFeldmanCommitment) != safecast.ToInt(protocol.Threshold()) {
		return errs.NewLength("len(previous feldman commitment) == %d != t == %d", len(r1b.PreviousFeldmanCommitment), protocol.Threshold())
	}
	return nil
}
