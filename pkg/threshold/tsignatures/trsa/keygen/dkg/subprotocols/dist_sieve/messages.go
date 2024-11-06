package dist_sieve

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/mul_n"
)

var (
	_ network.Message[types.ThresholdProtocol] = (*Round1P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round2P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round3Broadcast)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round4Broadcast)(nil)
)

type Round1P2P struct {
	AShare *replicated.IntShare
}

type Round2P2P = mul_n.Round1P2P

type Round3Broadcast struct {
	AModFour uint
}

type Round4Broadcast struct {
	PShareAdjust uint
}

func (m *Round4Broadcast) Validate(protocol types.ThresholdProtocol) error {
	return nil
}

func (m *Round3Broadcast) Validate(protocol types.ThresholdProtocol) error {
	return nil
}

func (r *Round1P2P) Validate(protocol types.ThresholdProtocol) error {
	return nil
}
