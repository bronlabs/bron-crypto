package hjky

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/pedersen"
)

type Round1Broadcast = pedersen.Round1Broadcast
type Round1P2P = pedersen.Round1P2P

func (p *Participant) Round1() (*Round1Broadcast, types.RoundMessages[*Round1P2P], error) {
	if p.round != 1 {
		return nil, nil, errs.NewRound("round mismatch %d != 1", p.round)
	}
	round1broadcast, round1p2p, err := p.PedersenParty.Round1(p.PedersenParty.Protocol.Curve().ScalarField().Zero())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not compute round 1 of pedersen with free coefficient of zero")
	}
	p.round++
	return round1broadcast, round1p2p, nil
}

func (p *Participant) Round2(round1outputBroadcast types.RoundMessages[*Round1Broadcast], round1outputP2P types.RoundMessages[*Round1P2P]) (sample Sample, publicKeySharesMap ds.Map[types.IdentityKey, curves.Point], feldmanCommitmentVector []curves.Point, err error) {
	if p.round != 2 {
		return nil, nil, nil, errs.NewRound("round mismatch %d != 2", p.round)
	}
	keyShare, publicKeyShares, err := p.PedersenParty.Round2(round1outputBroadcast, round1outputP2P)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not compute round 2 of pedersen")
	}
	if keyShare.Share.IsZero() {
		return nil, nil, nil, errs.NewIsZero("sample itself is zero")
	}
	p.round++
	return keyShare.Share, publicKeyShares.Shares, publicKeyShares.FeldmanCommitmentVector, nil
}
