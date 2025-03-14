package refresh

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/hjky"
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
	if len(r1b.PreviousFeldmanCommitment) != int(protocol.Threshold()) {
		return errs.NewLength("len(previous feldman commitment) == %d != t == %d", len(r1b.PreviousFeldmanCommitment), protocol.Threshold())
	}
	return nil
}
