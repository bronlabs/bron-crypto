package recovery

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/polynomials/interpolation/lagrange"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

func (p *Participant) Round1() (*Round1Broadcast, network.RoundMessages[*Round1P2P], error) {
	// Validation
	if err := p.InRound(1); err != nil {
		return nil, nil, errs.Forward(err)
	}

	// step 1.1
	round1broadcast, round1p2p, err := p.sampler.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not compute round 1 of zero share sampler")
	}

	p.NextRound()
	return round1broadcast, round1p2p, nil
}

func (p *Participant) Round2(round1broadcast network.RoundMessages[*Round1Broadcast], round1p2p network.RoundMessages[*Round1P2P]) (network.RoundMessages[*Round2P2P], error) {
	// Validation, round1broadcast and round1p2p delegated to sampler.Round2
	if err := p.InRound(2); err != nil {
		return nil, errs.Forward(err)
	}

	output := network.NewRoundMessages[*Round2P2P]()

	// step 2.1
	sample, _, _, err := p.sampler.Round2(round1broadcast, round1p2p)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not sample a zero share")
	}
	// step 2.2
	wrappedSample := &shamir.Share{
		Id:    uint(p.SharingId()),
		Value: sample,
	}

	partiesOfAdditiveConversion := make([]uint, len(p.sortedPresentRecoverersList)+1) // recoverers and lost party, all share samples of zero.
	lostPartySharingId, exists := p.sampler.PedersenParty.SharingConfig.Reverse().Get(p.lostPartyIdentityKey)
	if !exists {
		return nil, errs.NewMissing("could not find lost party sharing id")
	}
	partiesOfAdditiveConversion[0] = uint(lostPartySharingId)
	for i := 0; i < len(p.sortedPresentRecoverersList); i++ {
		recovererSharingId, exists := p.sampler.PedersenParty.SharingConfig.Reverse().Get(p.sortedPresentRecoverersList[i]) // 0'th identity is that of the lost party, hence indexing at i+1
		if !exists {
			return nil, errs.NewMissing("couldn't find sharing id for recoverer %d", i)
		}
		partiesOfAdditiveConversion[i+1] = uint(recovererSharingId)
	}
	p.additiveShareOfZero, err = wrappedSample.ToAdditive(partiesOfAdditiveConversion)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert sampled zero share to additive form")
	}

	if !p.IsRecoverer() {
		p.NextRound()
		return output, nil
	}

	curve := p.Protocol().Curve()

	// step 2.3.1
	lostPartySharingIdScalar := curve.ScalarField().New(uint64(lostPartySharingId))
	recovererSharingIdScalar := make([]curves.Scalar, len(p.sortedPresentRecoverersList))
	myIndex := -1
	for i, recovererSharingId := range partiesOfAdditiveConversion[1:] { // 0th index is the lost party
		recovererSharingIdScalar[i] = curve.ScalarField().New(uint64(recovererSharingId))
		if uint(p.SharingId()) == recovererSharingId {
			myIndex = i
		}
	}
	if myIndex == -1 {
		return nil, errs.NewMissing("could not find my lagrange basis index")
	}
	lx, err := lagrange.L_i(curve, myIndex, recovererSharingIdScalar, lostPartySharingIdScalar)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not compute lagrange basis polynomial at x=%d", lostPartySharingId)
	}
	// step 2.3.2
	s := lx.Mul(p.signingKeyShare.Share)
	// step 2.3.3
	sHat := s.Add(p.additiveShareOfZero)
	// step 2.3.4
	output.Put(p.lostPartyIdentityKey, &Round2P2P{
		BlindedPartiallyRecoveredShare: sHat,
	})

	p.LastRound()
	return output, nil
}

func (p *Participant) Round3(round2output network.RoundMessages[*Round2P2P]) (*tsignatures.SigningKeyShare, error) {
	// Validation
	if err := p.InRound(3); err != nil {
		return nil, errs.Forward(err)
	}
	if err := network.ValidateMessages(p.Protocol().Participants(), p.IdentityKey(), round2output); err != nil {
		return nil, errs.WrapValidation(err, "invalid round 2 P2P messages")
	}

	// step 3.1
	res := p.additiveShareOfZero // this, added to all blinded share, will all cancel out to zero
	for _, recoverer := range p.sortedPresentRecoverersList {
		receivedMessage, _ := round2output.Get(recoverer)
		res = res.Add(receivedMessage.BlindedPartiallyRecoveredShare)
	}
	// step 3.2
	partialPublicKey, exists := p.publicKeyShares.Shares.Get(p.lostPartyIdentityKey)
	if !exists {
		return nil, errs.NewMissing("could not find lost party partial public key")
	}
	if !p.Protocol().Curve().ScalarBaseMult(res).Equal(partialPublicKey) {
		return nil, errs.NewTotalAbort(nil, "recovered partial key is incompatible")
	}

	// step 3.3
	signingKeyShare := &tsignatures.SigningKeyShare{
		Share:     res,
		PublicKey: p.publicKeyShares.PublicKey,
	}
	if err := signingKeyShare.Validate(p.Protocol()); err != nil {
		return nil, errs.WrapValidation(err, "reconstructed signing key share")
	}

	p.LastRound()
	return signingKeyShare, nil
}
