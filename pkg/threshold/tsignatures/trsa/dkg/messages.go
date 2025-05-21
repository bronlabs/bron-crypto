package dkg

import (
	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
)

var (
	_ network.Message[types.ThresholdProtocol] = (*Round1Broadcast)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round1P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round2Broadcast)(nil)
)

type Round1Broadcast struct {
	N *saferith.Nat
}

func (*Round1Broadcast) Validate(_ types.ThresholdProtocol) error {
	return nil
}

type Round1P2P struct {
	DShare *rep23.IntShare
}

func (*Round1P2P) Validate(_ types.ThresholdProtocol) error {
	return nil
}

type Round2Broadcast struct {
	VShare1 *rep23.IntExpShare
	VShare2 *rep23.IntExpShare
}

func (m *Round2Broadcast) Validate(_ types.ThresholdProtocol) error {
	if m.VShare1 == nil || m.VShare2 == nil {
		return errs.NewValidation("nil share")
	}

	return nil
}
