package dkg

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/dkg/gennaro"
	"github.com/copperexchange/knox-primitives/pkg/signatures/bls"
	tbls "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tbls/boldyreva02"
)

type Round1Broadcast = gennaro.Round1Broadcast
type Round1P2P = gennaro.Round1P2P

type Round2Broadcast = gennaro.Round2Broadcast

func (p *Participant[K]) Round1() (*Round1Broadcast, map[helper_types.IdentityHash]*Round1P2P, error) {
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

func (p *Participant[K]) Round2(round1outputBroadcast map[helper_types.IdentityHash]*Round1Broadcast, round1outputP2P map[helper_types.IdentityHash]*Round1P2P) (*Round2Broadcast, error) {
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

func (p *Participant[K]) Round3(round2output map[helper_types.IdentityHash]*Round2Broadcast) (*tbls.Shard[K], error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}
	signingKeyShareVanilla, publicKeyShareVanilla, err := p.gennaroParty.Round3(round2output)
	if err != nil {
		return nil, errs.WrapFailed(err, "gennaro round 2 failed")
	}

	share, ok := signingKeyShareVanilla.Share.(curves.PairingScalar)
	if !ok {
		return nil, errs.NewInvalidType("share was not a pairing scalar")
	}
	publicKeyPoint, ok := signingKeyShareVanilla.PublicKey.(curves.PairingPoint)
	if !ok {
		return nil, errs.NewInvalidType("share was not a pairing point")
	}
	sharesMap := make(map[helper_types.IdentityHash]curves.PairingPoint, len(publicKeyShareVanilla.SharesMap))
	for id, point := range publicKeyShareVanilla.SharesMap {
		pairingPoint, ok := point.(curves.PairingPoint)
		if !ok {
			return nil, errs.NewInvalidType("point was not a pairing point")
		}
		sharesMap[id] = pairingPoint
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
			PublicKey: publicKey,
			SharesMap: sharesMap,
		},
	}, nil
}
