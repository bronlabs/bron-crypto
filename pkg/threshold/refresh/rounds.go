package refresh

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/hjky"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

func (p *Participant) Round1() (*Round1Broadcast, network.RoundMessages[*Round1P2P], error) {
	// Validation
	if p.Round != 1 {
		return nil, nil, errs.NewRound("Running round %d but participant expected round %d", 1, p.Round)
	}

	samplerRound1Broadcast, samplerRound1P2P, err := p.sampler.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not finish round 1 of hjky sampler")
	}

	p.Round++
	return &Round1Broadcast{
		Sampler:                   samplerRound1Broadcast,
		PreviousFeldmanCommitment: p.publicKeyShares.FeldmanCommitmentVector,
	}, samplerRound1P2P, nil
}

func (p *Participant) Round2(round1outputBroadcast network.RoundMessages[*Round1Broadcast], round1outputP2P network.RoundMessages[*Round1P2P]) (*tsignatures.SigningKeyShare, *tsignatures.PartialPublicKeys, error) {
	// Validation
	if p.Round != 2 {
		return nil, nil, errs.NewRound("Running round %d but participant expected round %d", 2, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol().Participants(), p.IdentityKey(), round1outputBroadcast, int(p.Protocol().Threshold())); err != nil {
		return nil, nil, errs.WrapValidation(err, "invalid round 1 broadcast messages")
	}
	if err := network.ValidateMessages(p.Protocol().Participants(), p.IdentityKey(), round1outputP2P); err != nil {
		return nil, nil, errs.WrapValidation(err, "invalid round 1 p2p messages")
	}

	combinedCommitmentVectors := map[types.SharingID][]curves.Point{}
	combinedCommitmentVectors[p.SharingId()] = make([]curves.Point, p.Protocol().Threshold())
	for i := uint(0); i < p.Protocol().Threshold(); i++ {
		combinedCommitmentVectors[p.SharingId()][i] = p.sampler.PedersenParty.State.Commitments[i].Add(p.publicKeyShares.FeldmanCommitmentVector[i])
	}

	samplerRound2BroadcastInput := network.NewRoundMessages[*hjky.Round1Broadcast]()

	for senderSharingIdUint := uint(1); senderSharingIdUint <= p.Protocol().TotalParties(); senderSharingIdUint++ {
		senderSharingId := types.SharingID(senderSharingIdUint)
		if senderSharingId == p.SharingId() {
			continue
		}

		senderIdentityKey, exists := p.sampler.PedersenParty.SharingConfig.Get(senderSharingId)
		if !exists {
			return nil, nil, errs.NewMissing("can't find identity key of sharing id %d", senderSharingId)
		}
		broadcastedMessageFromSender, _ := round1outputBroadcast.Get(senderIdentityKey)
		senderOldCommitmentVector := broadcastedMessageFromSender.PreviousFeldmanCommitment
		samplerRound2BroadcastInput.Put(senderIdentityKey, broadcastedMessageFromSender.Sampler)

		combinedCommitmentVectors[senderSharingId] = make([]curves.Point, p.Protocol().Threshold())
		for i := uint(0); i < p.Protocol().Threshold(); i++ {
			combinedCommitmentVectors[senderSharingId][i] = senderOldCommitmentVector[i].Add(broadcastedMessageFromSender.Sampler.Ci[i])
		}
	}

	sample, _, _, err := p.sampler.Round2(samplerRound2BroadcastInput, round1outputP2P)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not run round 2 of sampler")
	}

	publicKeySharesMap, err := dkg.ConstructPublicKeySharesMap(p.Protocol(), combinedCommitmentVectors, p.sampler.PedersenParty.SharingConfig)
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
	myPublicKeyShare := p.Protocol().Curve().ScalarBaseMult(refreshedSigningKeyShare.Share)
	if !myPublicKeyShare.Equal(myPresumedPublicKeyShare) {
		return nil, nil, errs.NewFailed("did not calculate my public key share correctly")
	}

	publicKeyShares := &tsignatures.PartialPublicKeys{
		PublicKey:               refreshedSigningKeyShare.PublicKey,
		Shares:                  publicKeySharesMap,
		FeldmanCommitmentVector: combinedCommitmentVectors[p.SharingId()],
	}
	if err := publicKeyShares.Validate(p.Protocol()); err != nil {
		return nil, nil, errs.WrapValidation(err, "couldn't verify public key shares")
	}

	p.Terminate()
	return refreshedSigningKeyShare, publicKeyShares, nil
}
