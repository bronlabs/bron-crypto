package dkg

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro"
	tbls "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
)

type Round1Broadcast = gennaro.Round1Broadcast
type Round1P2P = gennaro.Round1P2P

type Round2Broadcast = gennaro.Round2Broadcast

func (p *Participant[K]) Round1() (*Round1Broadcast, types.RoundMessages[*Round1P2P], error) {
	if p.round != 1 {
		return nil, nil, errs.NewRound("round mismatch %d != 1", p.round)
	}
	outputBroadcast, outputP2P, err := p.gennaroParty.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "gennaro round 1 failed")
	}
	p.round++
	return outputBroadcast, outputP2P, nil
}

func (p *Participant[K]) Round2(round1outputBroadcast types.RoundMessages[*Round1Broadcast], round1outputP2P types.RoundMessages[*Round1P2P]) (*Round2Broadcast, error) {
	if p.round != 2 {
		return nil, errs.NewRound("round mismatch %d != 2", p.round)
	}
	output, err := p.gennaroParty.Round2(round1outputBroadcast, round1outputP2P)
	if err != nil {
		return nil, errs.WrapFailed(err, "gennaro round 2 failed")
	}
	p.round++
	return output, nil
}

func (p *Participant[K]) Round3(round2output types.RoundMessages[*Round2Broadcast]) (*tbls.Shard[K], error) {
	if p.round != 3 {
		return nil, errs.NewRound("round mismatch %d != 3", p.round)
	}
	signingKeyShareVanilla, publicKeyShares, err := p.gennaroParty.Round3(round2output)
	if err != nil {
		return nil, errs.WrapFailed(err, "gennaro round 2 failed")
	}

	share := signingKeyShareVanilla.Share
	publicKeyPoint, ok := signingKeyShareVanilla.PublicKey.(curves.PairingPoint)
	if !ok {
		return nil, errs.NewType("share was not a pairing point")
	}
	publicKey := &bls.PublicKey[K]{
		Y: publicKeyPoint,
	}

	p.round++
	return &tbls.Shard[K]{
		SigningKeyShare: &tbls.SigningKeyShare[K]{
			Share:     share,
			PublicKey: publicKey,
		},
		PublicKeyShares: &tbls.PublicKeyShares[K]{
			PublicKey:               publicKey,
			Shares:                  publicKeyShares.Shares,
			FeldmanCommitmentVector: publicKeyShares.FeldmanCommitmentVector,
		},
	}, nil
}
