package refresh

import (
	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/errs"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/threshold/dkg"
	"github.com/copperexchange/knox-primitives/pkg/threshold/sharing/zero/hjky"
	"github.com/copperexchange/knox-primitives/pkg/threshold/tsignatures"
)

type Round1Broadcast struct {
	Sampler                   *hjky.Round1Broadcast
	PreviousFeldmanCommitment []curves.Point

	_ helper_types.Incomparable
}

type Round1P2P = hjky.Round1P2P

func (p *Participant) Round1() (*Round1Broadcast, map[helper_types.IdentityHash]*Round1P2P, error) {
	if p.round != 1 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}

	samplerRound1Broadcast, samplerRound1P2P, err := p.sampler.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not finish round 1 of hjky sampler")
	}

	p.round++
	return &Round1Broadcast{
		Sampler:                   samplerRound1Broadcast,
		PreviousFeldmanCommitment: p.publicKeyShares.FeldmanCommitmentVector,
	}, samplerRound1P2P, nil
}

func (p *Participant) Round2(round1outputBroadcast map[helper_types.IdentityHash]*Round1Broadcast, round1outputP2P map[helper_types.IdentityHash]*Round1P2P) (*tsignatures.SigningKeyShare, *tsignatures.PublicKeyShares, error) {
	if p.round != 2 {
		return nil, nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}
	combinedCommitmentVectors := map[int][]curves.Point{}
	combinedCommitmentVectors[p.GetSharingId()] = make([]curves.Point, p.GetCohortConfig().Protocol.Threshold)
	for i := 0; i < p.GetCohortConfig().Protocol.Threshold; i++ {
		combinedCommitmentVectors[p.GetSharingId()][i] = p.sampler.PedersenParty.State.Commitments[i].Add(p.publicKeyShares.FeldmanCommitmentVector[i])
	}

	samplerRound2BroadcastInput := make(map[helper_types.IdentityHash]*hjky.Round1Broadcast)

	for senderSharingId := 1; senderSharingId <= p.GetCohortConfig().Protocol.TotalParties; senderSharingId++ {
		if senderSharingId == p.GetSharingId() {
			continue
		}

		senderIdentityKey, exists := p.sampler.PedersenParty.SharingIdToIdentityKey[senderSharingId]
		if !exists {
			return nil, nil, errs.NewMissing("can't find identity key of sharing id %d", senderSharingId)
		}
		broadcastedMessageFromSender, exists := round1outputBroadcast[senderIdentityKey.Hash()]
		if !exists {
			return nil, nil, errs.NewMissing("do not have broadcasted message of the sender with sharing id %d", senderSharingId)
		}

		senderOldCommitmentVector := broadcastedMessageFromSender.PreviousFeldmanCommitment
		if len(senderOldCommitmentVector) != p.GetCohortConfig().Protocol.Threshold {
			return nil, nil, errs.NewMissing("do not have sender %d old commitment vector", senderSharingId)
		}
		samplerRound2BroadcastInput[senderIdentityKey.Hash()] = broadcastedMessageFromSender.Sampler

		combinedCommitmentVectors[senderSharingId] = make([]curves.Point, p.GetCohortConfig().Protocol.Threshold)
		for i := 0; i < p.GetCohortConfig().Protocol.Threshold; i++ {
			combinedCommitmentVectors[senderSharingId][i] = senderOldCommitmentVector[i].Add(broadcastedMessageFromSender.Sampler.Ci[i])
		}
	}

	sample, _, _, err := p.sampler.Round2(samplerRound2BroadcastInput, round1outputP2P)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run round 2 of sampler")
	}

	publicKeySharesMap, err := dkg.ConstructPublicKeySharesMap(p.GetCohortConfig(), combinedCommitmentVectors, p.sampler.PedersenParty.SharingIdToIdentityKey)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't derive public key shares")
	}
	refreshedSigningKeyShare := &tsignatures.SigningKeyShare{
		Share:     p.signingKeyShare.Share.Add(sample),
		PublicKey: p.publicKeyShares.PublicKey,
	}

	myPresumedPublicKeyShare := publicKeySharesMap[p.GetIdentityKey().Hash()]
	myPublicKeyShare := p.GetCohortConfig().CipherSuite.Curve.ScalarBaseMult(refreshedSigningKeyShare.Share)
	if !myPublicKeyShare.Equal(myPresumedPublicKeyShare) {
		return nil, nil, errs.NewFailed("did not calculate my public key share correctly")
	}

	publicKeyShares := &tsignatures.PublicKeyShares{
		Curve:                   p.GetCohortConfig().CipherSuite.Curve,
		PublicKey:               refreshedSigningKeyShare.PublicKey,
		SharesMap:               publicKeySharesMap,
		FeldmanCommitmentVector: combinedCommitmentVectors[p.GetSharingId()],
	}
	if err := publicKeyShares.Validate(p.GetCohortConfig()); err != nil {
		return nil, nil, errs.WrapVerificationFailed(err, "couldn't verify public key shares")
	}

	p.round++
	return refreshedSigningKeyShare, publicKeyShares, nil
}
