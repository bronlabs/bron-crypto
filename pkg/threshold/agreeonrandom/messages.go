package agreeonrandom

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	hashcommitments "github.com/bronlabs/krypton-primitives/pkg/commitments/hash"
	"github.com/bronlabs/krypton-primitives/pkg/network"
)

var _ network.Message[types.Protocol] = (*Round1Broadcast)(nil)
var _ network.Message[types.Protocol] = (*Round2Broadcast)(nil)

type Round1Broadcast struct {
	Commitment hashcommitments.Commitment

	_ ds.Incomparable
}

type Round2Broadcast struct {
	Ri      curves.Scalar
	Opening hashcommitments.Witness

	_ ds.Incomparable
}

func (*Round1Broadcast) Validate(types.Protocol) error {
	// if err := r1b.Commitment.Validate(); err != nil {
	//	return errs.WrapValidation(err, "invalid commitment")
	//}
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
	// if err := r2b.Opening.Validate(); err != nil {
	//	return errs.WrapValidation(err, "invalid opening")
	//}
	return nil
}
