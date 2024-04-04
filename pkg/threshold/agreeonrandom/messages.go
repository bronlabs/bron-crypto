package agreeonrandom

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/network"
)

var _ network.Message[types.Protocol] = (*Round1Broadcast)(nil)
var _ network.Message[types.Protocol] = (*Round2Broadcast)(nil)

type Round1Broadcast struct {
	Commitment commitments.Commitment

	_ ds.Incomparable
}

type Round2Broadcast struct {
	Ri      curves.Scalar
	Witness commitments.Witness

	_ ds.Incomparable
}

func (r1b *Round1Broadcast) Validate(protocol types.Protocol) error {
	if len(r1b.Commitment) == 0 {
		return errs.NewSize("commitment is empty")
	}
	return nil
}

func (r2b *Round2Broadcast) Validate(protocol types.Protocol) error {
	if r2b.Ri == nil {
		return errs.NewIsNil("r_i")
	}
	if r2b.Ri.ScalarField().Curve() != protocol.Curve() {
		return errs.NewCurve("r_i curve %s is not protocol curve %s", r2b.Ri.ScalarField().Curve().Name(), protocol.Curve().Name())
	}
	if r2b.Ri.IsZero() {
		return errs.NewIsZero("r_i is zero")
	}
	if len(r2b.Witness) == 0 {
		return errs.NewSize("witness is empty")
	}
	return nil
}
