package dkg

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/dkg/pedersen"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
)

type Round1Broadcast = pedersen.Round1Broadcast

type Round2Broadcast = pedersen.Round2Broadcast

type Round2P2P = pedersen.Round2P2P

func (p *DKGParticipant) Round1() (*Round1Broadcast, error) {
	return p.pedersenParty.Round1()
}

func (p *DKGParticipant) Round2(round1output map[integration.IdentityKey]*Round1Broadcast) (*Round2Broadcast, map[integration.IdentityKey]*Round2P2P, error) {
	return p.pedersenParty.Round2(round1output)
}

func (p *DKGParticipant) Round3(round2outputBroadcast map[integration.IdentityKey]*Round2Broadcast, round2outputP2P map[integration.IdentityKey]*Round2P2P) (*frost.SigningKeyShare, *frost.PublicKeyShares, error) {
	return p.pedersenParty.Round3(round2outputBroadcast, round2outputP2P)
}
