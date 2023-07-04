package dkg

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/dkg/pedersen"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tschnorr/frost"
)

type Round1Broadcast = pedersen.Round1Broadcast

type Round2Broadcast = pedersen.Round2Broadcast

type Round2P2P = pedersen.Round2P2P

func (p *Participant) Round1() (*Round1Broadcast, error) {
	output, err := p.pedersenParty.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "pedersen round 1 failed")
	}
	return output, nil
}

func (p *Participant) Round2(round1output map[integration.IdentityKey]*Round1Broadcast) (*Round2Broadcast, map[integration.IdentityKey]*Round2P2P, error) {
	outputBroadcast, outputP2P, err := p.pedersenParty.Round2(round1output)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "pedersen round 2 failed")
	}
	return outputBroadcast, outputP2P, nil
}

func (p *Participant) Round3(round2outputBroadcast map[integration.IdentityKey]*Round2Broadcast, round2outputP2P map[integration.IdentityKey]*Round2P2P) (*frost.SigningKeyShare, *frost.PublicKeyShares, error) {
	signingKeyShare, publicKeyShares, err := p.pedersenParty.Round3(round2outputBroadcast, round2outputP2P)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "pedersen round 3 failed")
	}
	return signingKeyShare, publicKeyShares, nil
}
