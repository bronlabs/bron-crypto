package inv_mod

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/mul_two"
)

var (
	_ network.Message[types.ThresholdProtocol] = (*Round1P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round2P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round3Broadcast)(nil)
)

type Round1P2P struct {
	LambdaShare *replicated.IntShare
	RShare      *replicated.IntShare
}

type Round2P2P = mul_two.Round1P2P

type Round3Broadcast struct {
	GammaShare *replicated.IntShare
}

func (m *Round1P2P) Validate(protocol types.ThresholdProtocol) error {
	return nil
}

func (m *Round3Broadcast) Validate(protocol types.ThresholdProtocol) error {
	return nil
}
