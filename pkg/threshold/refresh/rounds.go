package refresh

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/network"
	feldman_vss "github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures"
)

func (p *Participant) Round1() (*Round1Broadcast, network.RoundMessages[types.ThresholdProtocol, *Round1P2P], error) {
	// Validation
	if p.Round != 1 {
		return nil, nil, errs.NewRound("Running round %d but participant expected round %d", 1, p.Round)
	}

	samplerRound1Broadcast, samplerRound1P2P, err := p.sampler.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not finish round 1 of hjky sampler")
	}

	p.Round++
	return samplerRound1Broadcast, samplerRound1P2P, nil
}

func (p *Participant) Round2(round1outputBroadcast network.RoundMessages[types.ThresholdProtocol, *Round1Broadcast], round1outputP2P network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) (*tsignatures.SigningKeyShare, *tsignatures.PartialPublicKeys, error) {
	// Validation
	if p.Round != 2 {
		return nil, nil, errs.NewRound("Running round %d but participant expected round %d", 2, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.Protocol.Participants(), p.IdentityKey(), round1outputBroadcast); err != nil {
		return nil, nil, errs.WrapValidation(err, "invalid round 2 input broadcast messages")
	}
	if err := network.ValidateMessages(p.Protocol, p.Protocol.Participants(), p.IdentityKey(), round1outputP2P); err != nil {
		return nil, nil, errs.WrapValidation(err, "invalid round 2 input P2P messages")
	}

	zeroShare, zeroPublicShares, zeroVerification, err := p.sampler.Round2(round1outputBroadcast, round1outputP2P)
	if err != nil {
		return nil, nil, errs.WrapValidation(err, "cannot run round2")
	}

	feldmanScheme, err := feldman_vss.NewScheme(p.Protocol.Threshold(), p.Protocol.TotalParties(), p.Protocol.Curve())
	if err != nil {
		return nil, nil, errs.WrapValidation(err, "cannot create Feldman-VSS")
	}

	combinedShare := p.signingKeyShare.Share.Add(zeroShare)
	combinedPublicKey := zeroVerification[0].Add(p.signingKeyShare.PublicKey)
	combinedVerification := feldmanScheme.VerificationAdd(p.publicKeyShares.FeldmanCommitmentVector, zeroVerification)
	combinedPublicShares := hashmap.NewComparableHashMap[types.SharingID, curves.Point]()
	for sharingId, value := range p.publicKeyShares.Shares.Iter() {
		ps, _ := zeroPublicShares.Get(sharingId)
		combinedPublicShares.Put(sharingId, value.Add(ps))
	}

	sks := &tsignatures.SigningKeyShare{
		Share:     combinedShare,
		PublicKey: combinedPublicKey,
	}
	pks := &tsignatures.PartialPublicKeys{
		PublicKey:               combinedPublicKey,
		Shares:                  combinedPublicShares,
		FeldmanCommitmentVector: combinedVerification,
	}

	return sks, pks, nil
}
