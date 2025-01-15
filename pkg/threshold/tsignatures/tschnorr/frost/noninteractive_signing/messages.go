package noninteractive_signing

import (
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/network"
)

var _ network.Message[types.ThresholdProtocol] = (*Round1Broadcast)(nil)

type Round1Broadcast struct {
	Tau         int
	Commitments []*AttestedCommitmentToNoncePair

	_ ds.Incomparable
}

func (r1b *Round1Broadcast) Validate(protocol types.ThresholdProtocol) error {
	if r1b.Tau < 1 {
		return errs.NewSize("Tau is less than 1")
	}
	if r1b.Commitments == nil {
		return errs.NewIsNil("Commitments is nil")
	}
	return nil
}
