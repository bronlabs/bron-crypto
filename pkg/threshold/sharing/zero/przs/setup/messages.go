package setup

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/network"
)

var _ network.MessageLike = (*Round1P2P)(nil)
var _ network.MessageLike = (*Round2P2P)(nil)

type Round1P2P struct {
	Commitment commitments.Commitment

	_ ds.Incomparable
}

type Round2P2P struct {
	Message []byte
	Witness commitments.Witness

	_ ds.Incomparable
}

func (r1p2p *Round1P2P) Validate(none ...int) error {
	if r1p2p.Commitment == nil {
		return errs.NewIsNil("commitment")
	}
	return nil
}

func (r2p2p *Round2P2P) Validate(none ...int) error {
	if len(r2p2p.Message) == 0 {
		return errs.NewIsNil("message")
	}
	if len(r2p2p.Witness) == 0 {
		return errs.NewIsNil("witness")
	}
	return nil
}
