package dkg

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/pedersen"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
)

type Round1Broadcast = pedersen.Round1Broadcast

type Round1P2P = pedersen.Round1P2P

func (p *Participant) Round1() (*Round1Broadcast, types.RoundMessages[*Round1P2P], error) {
	outputBroadcast, outputP2P, err := p.pedersenParty.Round1(nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "pedersen round 1 failed")
	}
	return outputBroadcast, outputP2P, nil
}

func (p *Participant) Round2(round1outputBroadcast types.RoundMessages[*Round1Broadcast], round1outputP2P types.RoundMessages[*Round1P2P]) (*frost.Shard, error) {
	signingKeyShare, publicKeyShares, err := p.pedersenParty.Round2(round1outputBroadcast, round1outputP2P)
	if err != nil {
		return nil, errs.WrapFailed(err, "pedersen round 2 failed")
	}
	return &frost.Shard{
		SigningKeyShare: signingKeyShare,
		PublicKeyShares: publicKeyShares,
	}, nil
}
