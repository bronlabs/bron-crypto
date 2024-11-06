package dkg

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/inv_mod"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/prob_prime_two_three"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/keygen/dkg/subprotocols/sieve"
)

var (
	_ network.Message[types.ThresholdProtocol] = (*Round1P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round2P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round3Broadcast)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round4P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round5P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round6P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round7P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round8P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round9P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round10P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round11P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round12P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round13P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round14Broadcast)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round16P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round17P2P)(nil)
	_ network.Message[types.ThresholdProtocol] = (*Round18Broadcast)(nil)
)

type Round1P2P = sieve.Round1P2P

type Round2P2P = sieve.Round2P2P

type Round3Broadcast = sieve.Round3Broadcast

type Round4P2P struct {
	PProbPrimeR1 *prob_prime_two_three.Round1P2P
	QProbPrimeR1 *prob_prime_two_three.Round1P2P
}

type Round5P2P struct {
	PProbPrimeR2 *prob_prime_two_three.Round2P2P
	QProbPrimeR2 *prob_prime_two_three.Round2P2P
}

type Round6P2P struct {
	PProbPrimeR3 *prob_prime_two_three.Round3P2P
	QProbPrimeR3 *prob_prime_two_three.Round3P2P
}

type Round7P2P struct {
	PProbPrimeR4 *prob_prime_two_three.Round4P2P
	QProbPrimeR4 *prob_prime_two_three.Round4P2P
}

type Round8P2P struct {
	PProbPrimeR5 *prob_prime_two_three.Round5P2P
	QProbPrimeR5 *prob_prime_two_three.Round5P2P
}

type Round9P2P struct {
	PProbPrimeR6 *prob_prime_two_three.Round6P2P
	QProbPrimeR6 *prob_prime_two_three.Round6P2P
}

type Round10P2P struct {
	PProbPrimeR7 *prob_prime_two_three.Round7P2P
	QProbPrimeR7 *prob_prime_two_three.Round7P2P
}

type Round11P2P struct {
	PProbPrimeR8 *prob_prime_two_three.Round8P2P
	QProbPrimeR8 *prob_prime_two_three.Round8P2P
}

type Round12P2P struct {
	PProbPrimeR9 *prob_prime_two_three.Round9P2P
	QProbPrimeR9 *prob_prime_two_three.Round9P2P
}

type Round13P2P struct {
	PProbPrimeR10 *prob_prime_two_three.Round10P2P
	QProbPrimeR10 *prob_prime_two_three.Round10P2P
}

type Round14Broadcast struct {
	PProbPrimeR11 *prob_prime_two_three.Round11Broadcast
	QProbPrimeR11 *prob_prime_two_three.Round11Broadcast
}

type Round16P2P = inv_mod.Round1P2P

type Round17P2P = inv_mod.Round2P2P

type Round18Broadcast = inv_mod.Round3Broadcast

func (m *Round4P2P) Validate(protocol types.ThresholdProtocol) error {
	//TODO implement me
	panic("implement me")
}

func (m *Round5P2P) Validate(protocol types.ThresholdProtocol) error {
	//TODO implement me
	panic("implement me")
}

func (m *Round6P2P) Validate(protocol types.ThresholdProtocol) error {
	//TODO implement me
	panic("implement me")
}

func (m *Round7P2P) Validate(protocol types.ThresholdProtocol) error {
	//TODO implement me
	panic("implement me")
}

func (m *Round8P2P) Validate(protocol types.ThresholdProtocol) error {
	//TODO implement me
	panic("implement me")
}

func (m *Round9P2P) Validate(protocol types.ThresholdProtocol) error {
	//TODO implement me
	panic("implement me")
}

func (m *Round10P2P) Validate(protocol types.ThresholdProtocol) error {
	//TODO implement me
	panic("implement me")
}

func (m *Round11P2P) Validate(protocol types.ThresholdProtocol) error {
	//TODO implement me
	panic("implement me")
}

func (m *Round12P2P) Validate(protocol types.ThresholdProtocol) error {
	//TODO implement me
	panic("implement me")
}

func (m *Round13P2P) Validate(protocol types.ThresholdProtocol) error {
	//TODO implement me
	panic("implement me")
}

func (m *Round14Broadcast) Validate(protocol types.ThresholdProtocol) error {
	//TODO implement me
	panic("implement me")
}
