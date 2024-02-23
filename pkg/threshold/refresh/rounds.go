package refresh

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/hjky"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

type Round1Broadcast struct {
	Sampler                   *hjky.Round1Broadcast
	PreviousFeldmanCommitment []curves.Point

	_ ds.Incomparable
}

type Round1P2P = hjky.Round1P2P

func (p *Participant) Round1() (*Round1Broadcast, types.RoundMessages[*Round1P2P], error) {
	if p.round != 1 {
		return nil, nil, errs.NewRound("round mismatch %d != 1", p.round)
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

func (p *Participant) Round2(round1outputBroadcast types.RoundMessages[*Round1Broadcast], round1outputP2P types.RoundMessages[*Round1P2P]) (*tsignatures.SigningKeyShare, *tsignatures.PartialPublicKeys, error) {
	if p.round != 2 {
		return nil, nil, errs.NewRound("round mismatch %d != 2", p.round)
	}
	combinedCommitmentVectors := map[types.SharingID][]curves.Point{}
	combinedCommitmentVectors[p.SharingId()] = make([]curves.Point, p.protocol.Threshold())
	for i := uint(0); i < p.protocol.Threshold(); i++ {
		combinedCommitmentVectors[p.SharingId()][i] = p.sampler.PedersenParty.State.Commitments[i].Add(p.publicKeyShares.FeldmanCommitmentVector[i])
	}

	samplerRound2BroadcastInput := types.NewRoundMessages[*hjky.Round1Broadcast]()

	for senderSharingIdUint := uint(1); senderSharingIdUint <= p.protocol.TotalParties(); senderSharingIdUint++ {
		senderSharingId := types.SharingID(senderSharingIdUint)
		if senderSharingId == p.SharingId() {
			continue
		}

		senderIdentityKey, exists := p.sampler.PedersenParty.SharingConfig.Get(senderSharingId)
		if !exists {
			return nil, nil, errs.NewMissing("can't find identity key of sharing id %d", senderSharingId)
		}
		broadcastedMessageFromSender, exists := round1outputBroadcast.Get(senderIdentityKey)
		if !exists {
			return nil, nil, errs.NewMissing("do not have broadcasted message of the sender with sharing id %d", senderSharingId)
		}

		senderOldCommitmentVector := broadcastedMessageFromSender.PreviousFeldmanCommitment
		if len(senderOldCommitmentVector) != int(p.protocol.Threshold()) {
			return nil, nil, errs.NewMissing("do not have sender %d old commitment vector", senderSharingId)
		}
		samplerRound2BroadcastInput.Put(senderIdentityKey, broadcastedMessageFromSender.Sampler)

		combinedCommitmentVectors[senderSharingId] = make([]curves.Point, p.protocol.Threshold())
		for i := uint(0); i < p.protocol.Threshold(); i++ {
			combinedCommitmentVectors[senderSharingId][i] = senderOldCommitmentVector[i].Add(broadcastedMessageFromSender.Sampler.Ci[i])
		}
	}

	sample, _, _, err := p.sampler.Round2(samplerRound2BroadcastInput, round1outputP2P)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run round 2 of sampler")
	}

	publicKeySharesMap, err := dkg.ConstructPublicKeySharesMap(p.protocol, combinedCommitmentVectors, p.sampler.PedersenParty.SharingConfig)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't derive public key shares")
	}
	refreshedSigningKeyShare := &tsignatures.SigningKeyShare{
		Share:     p.signingKeyShare.Share.Add(sample),
		PublicKey: p.publicKeyShares.PublicKey,
	}

	myPresumedPublicKeyShare, exists := publicKeySharesMap.Get(p.IdentityKey())
	if !exists {
		return nil, nil, errs.NewMissing("couldn't find my own computed partial public key")
	}
	myPublicKeyShare := p.protocol.Curve().ScalarBaseMult(refreshedSigningKeyShare.Share)
	if !myPublicKeyShare.Equal(myPresumedPublicKeyShare) {
		return nil, nil, errs.NewFailed("did not calculate my public key share correctly")
	}

	publicKeyShares := &tsignatures.PartialPublicKeys{
		PublicKey:               refreshedSigningKeyShare.PublicKey,
		Shares:                  publicKeySharesMap,
		FeldmanCommitmentVector: combinedCommitmentVectors[p.SharingId()],
	}
	if err := publicKeyShares.Validate(p.protocol); err != nil {
		return nil, nil, errs.WrapValidation(err, "couldn't verify public key shares")
	}

	p.round++
	return refreshedSigningKeyShare, publicKeyShares, nil
}
