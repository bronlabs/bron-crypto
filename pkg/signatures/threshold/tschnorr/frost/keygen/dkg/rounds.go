package dkg

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/dkg/pedersen"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tschnorr/frost"
)

type Round2Broadcast = pedersen.Round2Broadcast

type Round2P2P = pedersen.Round2P2P

func (p *Participant) Round2() (*Round2Broadcast, map[integration.IdentityKey]*Round2P2P, error) {
	outputBroadcast, outputP2P, err := p.pedersenParty.Round2()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "pedersen round 1 failed")
	}
	return outputBroadcast, outputP2P, nil
}

func (p *Participant) Round3(round2outputBroadcast map[integration.IdentityKey]*Round2Broadcast, round2outputP2P map[integration.IdentityKey]*Round2P2P) (*frost.SigningKeyShare, *frost.PublicKeyShares, error) {
	signingKeyShare, publicKeyShares, err := p.pedersenParty.Round3(round2outputBroadcast, round2outputP2P)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "pedersen round 2 failed")
	}
	return signingKeyShare, publicKeyShares, nil
}
