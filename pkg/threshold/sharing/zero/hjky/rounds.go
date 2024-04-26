package hjky

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
)

func (p *Participant) Round1() (*Round1Broadcast, network.RoundMessages[types.ThresholdProtocol, *Round1P2P], error) {
	// Validation delegated to Pedersen.Round2
	round1broadcast, round1p2p, err := p.PedersenParty.Round1(p.PedersenParty.Protocol.Curve().ScalarField().Zero())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not compute round 1 of pedersen with free coefficient of zero")
	}

	return round1broadcast, round1p2p, nil
}

func (p *Participant) Round2(round1outputBroadcast network.RoundMessages[types.ThresholdProtocol, *Round1Broadcast], round1outputP2P network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) (sample Sample, publicKeySharesMap ds.Map[types.IdentityKey, curves.Point], feldmanCommitmentVector []curves.Point, err error) {
	// Validation delegated to pedersen.Round2
	keyShare, publicKeyShares, err := p.PedersenParty.Round2(round1outputBroadcast, round1outputP2P)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "could not compute round 2 of pedersen")
	}
	if keyShare.Share.IsZero() {
		return nil, nil, nil, errs.NewIsZero("sample itself is zero")
	}
	// This check is just for good measure. We already check this in Round 2 during message validation.
	if !publicKeyShares.PublicKey.IsIdentity() {
		return nil, nil, nil, errs.NewTotalAbort(nil, "the shares will not combine to zero")
	}

	return keyShare.Share, publicKeyShares.Shares, publicKeyShares.FeldmanCommitmentVector, nil
}
