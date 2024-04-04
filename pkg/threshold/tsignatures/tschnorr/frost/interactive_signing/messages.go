package interactive_signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
)

var _ network.Message[types.ThresholdSignatureProtocol] = (*Round1Broadcast)(nil)

type Round1Broadcast struct {
	Di curves.Point
	Ei curves.Point

	_ ds.Incomparable
}

func (r1b *Round1Broadcast) Validate(protocol types.ThresholdSignatureProtocol) error {
	if r1b.Di == nil {
		return errs.NewIsNil("Di is nil")
	}
	if r1b.Ei == nil {
		return errs.NewIsNil("Ei is nil")
	}
	return nil
}
