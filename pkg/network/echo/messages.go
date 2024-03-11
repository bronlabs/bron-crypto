package echo

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/network"
)

var _ network.MessageLike = (*Round1P2P)(nil)
var _ network.MessageLike = (*Round1P2P)(nil)

type Round1P2P struct {
	// InitiatorSignature is signature of Message. We use this to authenticate that the message is sent by the initiator.
	InitiatorSignature []byte
	Message            []byte

	_ ds.Incomparable
}

type Round2P2P struct {
	InitiatorSignature []byte
	Message            []byte

	_ ds.Incomparable
}

func (r1p2p *Round1P2P) Validate(none ...int) error {
	if len(r1p2p.InitiatorSignature) == 0 {
		return errs.NewSize("initiator signature is empty")
	}
	if len(r1p2p.Message) == 0 {
		return errs.NewIsNil("message is empty")
	}
	return nil
}

func (r2p2p *Round2P2P) Validate(none ...int) error {
	if len(r2p2p.InitiatorSignature) == 0 {
		return errs.NewSize("initiator signature is empty")
	}
	if len(r2p2p.Message) == 0 {
		return errs.NewIsNil("message is empty")
	}
	return nil
}
