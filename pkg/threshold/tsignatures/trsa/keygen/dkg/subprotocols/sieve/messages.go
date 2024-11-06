package sieve

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
	PShare *replicated.IntShare
	QShare *replicated.IntShare
}

func (r *Round1P2P) Validate(protocol types.ThresholdProtocol) error {
	return nil
}

type Round2P2P struct {
	MulPQR1 *mul_two.Round1P2P
}

func (r *Round2P2P) Validate(protocol types.ThresholdProtocol) error {
	return nil
}

type Round3Broadcast struct {
	NShare *replicated.IntShare
}

func (r *Round3Broadcast) Validate(protocol types.ThresholdProtocol) error {
	return nil
}
