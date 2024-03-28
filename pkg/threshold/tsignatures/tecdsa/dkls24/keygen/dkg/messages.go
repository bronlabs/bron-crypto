package dkg

import (
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/bbot"
	zeroSetup "github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/setup"
)

var _ network.Message = (*Round1P2P)(nil)
var _ network.Message = (*Round2P2P)(nil)

type Round1P2P struct {
	ZeroSampling *zeroSetup.Round1P2P
	BaseOTSender *bbot.Round1P2P

	_ ds.Incomparable
}

type Round2P2P struct {
	ZeroSampling   *zeroSetup.Round2P2P
	BaseOTReceiver *bbot.Round2P2P

	_ ds.Incomparable
}

func (r *Round1P2P) Validate(none ...int) error {
	if r.ZeroSampling == nil {
		return errs.NewIsNil("zero sampling message")
	}
	if r.BaseOTSender == nil {
		return errs.NewIsNil("base ot sender message")
	}
	return nil
}

func (r *Round2P2P) Validate(none ...int) error {
	if r.ZeroSampling == nil {
		return errs.NewIsNil("zero sampling message")
	}
	if r.BaseOTReceiver == nil {
		return errs.NewIsNil("base ot receiver message")
	}
	return nil
}
