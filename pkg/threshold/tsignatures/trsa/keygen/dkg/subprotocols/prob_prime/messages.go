package prob_prime

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/mul_n"
)

var (
	_ network.Message[types.ThresholdProtocol] = (*Round1P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round2P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round3P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round4P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round5P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round6Broadcast)(nil)
)

type Round1P2P struct {
	GammaShare *replicated.IntShare
}

type Round2P2P = mul_n.Round1P2P

type Round3P2P = mul_n.Round1P2P

type Round4P2P = mul_n.Round1P2P

type Round5P2P = mul_n.Round1P2P

type Round6Broadcast struct {
	ZShare *replicated.IntShare
}

func (m *Round1P2P) Validate(protocol types.ThresholdProtocol) error {
	return nil
}

func (m *Round6Broadcast) Validate(protocol types.ThresholdProtocol) error {
	return nil
}
