package setup

import (
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	hashcommitments "github.com/bronlabs/krypton-primitives/pkg/commitments/hash"
	"github.com/bronlabs/krypton-primitives/pkg/network"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/zero/rprzs"
)

var _ network.Message[types.Protocol] = (*Round1P2P)(nil)
var _ network.Message[types.Protocol] = (*Round2P2P)(nil)

type Round1P2P struct {
	Commitment hashcommitments.Commitment

	_ ds.Incomparable
}

type Round2P2P struct {
	Message []byte
	Opening hashcommitments.Witness

	_ ds.Incomparable
}

func (*Round1P2P) Validate(types.Protocol) error {
	// if err := r1p2p.Commitment.Validate(); err != nil {
	//	return errs.NewValidation("invalid commitment")
	//}
	return nil
}

func (r2p2p *Round2P2P) Validate(protocol types.Protocol) error {
	if len(r2p2p.Message) == 0 {
		return errs.NewIsNil("message")
	}
	if len(r2p2p.Message) != rprzs.LambdaBytes {
		return errs.NewLength("message")
	}
	// if err := r2p2p.Opening.Validate(); err != nil {
	//	return errs.NewValidation("invalid opening")
	//}
	return nil
}
