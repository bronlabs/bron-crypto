package dkg

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
)

type Round1Broadcast = gennaro.Round1Broadcast
type Round1P2P = gennaro.Round1P2P

type Round2Broadcast = gennaro.Round2Broadcast

func (p *Participant) Round1() (*Round1Broadcast, map[types.IdentityHash]*Round1P2P, error) {
	if p.round != 1 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}
	outputBroadcast, outputP2P, err := p.gennaroParty.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "gennaro round 1 failed")
	}
	p.round++
	return outputBroadcast, outputP2P, nil
}

func (p *Participant) Round2(round1outputBroadcast map[types.IdentityHash]*Round1Broadcast, round1outputP2P map[types.IdentityHash]*Round1P2P) (*Round2Broadcast, error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}
	output, err := p.gennaroParty.Round2(round1outputBroadcast, round1outputP2P)
	if err != nil {
		return nil, errs.WrapFailed(err, "gennaro round 2 failed")
	}
	p.round++
	return output, nil
}

func (p *Participant) Round3(round2output map[types.IdentityHash]*Round2Broadcast) (*lindell22.Shard, error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}
	signingKeyShare, publicKeyShare, err := p.gennaroParty.Round3(round2output)
	if err != nil {
		return nil, errs.WrapFailed(err, "gennaro round 2 failed")
	}
	p.round++
	return &lindell22.Shard{
		SigningKeyShare: signingKeyShare,
		PublicKeyShares: publicKeyShare,
	}, nil
}
