package noninteractive_signing

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/network"
)

var _ network.Message = (*Round1Broadcast)(nil)

type Round1Broadcast struct {
	Tau         int
	Commitments []*AttestedCommitmentToNoncePair

	_ ds.Incomparable
}

func (r1b *Round1Broadcast) Validate(none ...int) error {
	if r1b.Tau < 1 {
		return errs.NewSize("Tau is less than 1")
	}
	if r1b.Commitments == nil {
		return errs.NewIsNil("Commitments is nil")
	}
	return nil
}
