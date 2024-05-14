package setup

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/comm/hashcomm"
	"github.com/copperexchange/krypton-primitives/pkg/network"
)

var _ network.Message[types.Protocol] = (*Round1P2P)(nil)
var _ network.Message[types.Protocol] = (*Round2P2P)(nil)

type Round1P2P struct {
	Commitment *hashcomm.Commitment

	_ ds.Incomparable
}

type Round2P2P struct {
	Message []byte
	Opening *hashcomm.Opening

	_ ds.Incomparable
}

func (r1p2p *Round1P2P) Validate(protocol types.Protocol) error {
	if err := r1p2p.Commitment.Validate(); err != nil {
		return errs.NewValidation("invalid commitment")
	}
	return nil
}

func (r2p2p *Round2P2P) Validate(protocol types.Protocol) error {
	if len(r2p2p.Message) == 0 {
		return errs.NewIsNil("message")
	}
	if err := r2p2p.Opening.Validate(); err != nil {
		return errs.NewValidation("invalid witness")
	}
	return nil
}
