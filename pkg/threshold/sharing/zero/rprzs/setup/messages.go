package setup

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/rprzs"
	hashcommitments "github.com/copperexchange/krypton-primitives/pkg/vector_commitments/hash"
)

var _ network.Message[types.Protocol] = (*Round1P2P)(nil)
var _ network.Message[types.Protocol] = (*Round2P2P)(nil)

type Round1P2P struct {
	Commitment hashcommitments.Commitment

	_ ds.Incomparable
}

type Round2P2P struct {
	Message []byte
	Opening hashcommitments.Opening

	_ ds.Incomparable
}

func (*Round1P2P) Validate(protocol types.Protocol) error {
	return nil
}

func (r2p2p *Round2P2P) Validate(protocol types.Protocol) error {
	if len(r2p2p.Message) == 0 {
		return errs.NewIsNil("message")
	}
	if len(r2p2p.Message) != rprzs.LambdaBytes {
		return errs.NewLength("message")
	}
	return nil
}
