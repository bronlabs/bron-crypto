package prob_prime_two_three

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/mul_two"
)

var (
	_ network.Message[types.ThresholdProtocol] = (*Round1P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round2P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round3P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round4P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round5P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round6P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round7P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round8P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round9P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round10P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round11Broadcast)(nil)
)

type Round1P2P struct {
	GammaShare *replicated.IntShare
}

type Round2P2P struct {
	Mul12R1 *mul_two.Round1P2P
}

type Round3P2P struct {
	Mul123R1 *mul_two.Round1P2P
}

type Round4P2P struct {
	MulGammaAInvR1 *mul_two.Round1P2P
}

type Round5P2P struct {
	YMulR1 *mul_two.Round1P2P
}

type Round6P2P struct {
	ABMulR1 *mul_two.Round1P2P
	CDMulR1 *mul_two.Round1P2P
	EFMulR1 *mul_two.Round1P2P
	GHMulR1 *mul_two.Round1P2P
	IJMulR1 *mul_two.Round1P2P
	KLMulR1 *mul_two.Round1P2P
	MNMulR1 *mul_two.Round1P2P
	OPMulR1 *mul_two.Round1P2P
	QRMulR1 *mul_two.Round1P2P
}

type Round7P2P struct {
	ABCDMulR1 *mul_two.Round1P2P
	EFGHMulR1 *mul_two.Round1P2P
	IJKLMulR1 *mul_two.Round1P2P
	MNOPMulR1 *mul_two.Round1P2P
}

type Round8P2P struct {
	ABCDEFGHMulR1 *mul_two.Round1P2P
	IJKLMNOPMulR1 *mul_two.Round1P2P
}

type Round9P2P struct {
	ABCDEFGHIJKLMNOPMulR1 *mul_two.Round1P2P
}

type Round10P2P struct {
	ABCDEFGHIJKLMNOPQRMulR1 *mul_two.Round1P2P
}

type Round11Broadcast struct {
	ZShare *replicated.IntShare
}

func (m *Round11Broadcast) Validate(protocol types.ThresholdProtocol) error {
	return nil
}

func (m *Round10P2P) Validate(protocol types.ThresholdProtocol) error {
	return nil
}

func (m *Round9P2P) Validate(protocol types.ThresholdProtocol) error {
	return nil
}

func (m *Round8P2P) Validate(protocol types.ThresholdProtocol) error {
	return nil
}

func (m *Round7P2P) Validate(protocol types.ThresholdProtocol) error {
	return nil
}

func (m *Round6P2P) Validate(protocol types.ThresholdProtocol) error {
	return nil
}

func (m *Round5P2P) Validate(protocol types.ThresholdProtocol) error {
	return nil
}

func (m *Round4P2P) Validate(protocol types.ThresholdProtocol) error {
	return nil
}

func (m *Round1P2P) Validate(protocol types.ThresholdProtocol) error {
	return nil
}

func (m *Round2P2P) Validate(protocol types.ThresholdProtocol) error {
	return nil
}

func (m *Round3P2P) Validate(protocol types.ThresholdProtocol) error {
	return nil
}
