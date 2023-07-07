package dkg

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/dkg/pedersen"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tschnorr/frost"
)

type Round1Broadcast = pedersen.Round1Broadcast

type Round1P2P = pedersen.Round1P2P

func (p *Participant) Round1() (*Round1Broadcast, map[integration.IdentityKey]*Round1P2P, error) {
	outputBroadcast, outputP2P, err := p.pedersenParty.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "pedersen round 1 failed")
	}
	return outputBroadcast, outputP2P, nil
}

func (p *Participant) Round2(round1outputBroadcast map[integration.IdentityKey]*Round1Broadcast, round1outputP2P map[integration.IdentityKey]*Round1P2P) (*frost.SigningKeyShare, *frost.PublicKeyShares, error) {
	signingKeyShare, publicKeyShares, err := p.pedersenParty.Round2(round1outputBroadcast, round1outputP2P)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "pedersen round 2 failed")
	}
	return signingKeyShare, publicKeyShares, nil
}
