package gennaro

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	pedersen_comm "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures"
)

func (p *Participant) Round1() (r1bo *Round1Broadcast, err error) {
	if p.Round != 1 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 1, p.Round)
	}

	zi, err := p.Protocol.Curve().ScalarField().Random(p.Prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot sample scalar")
	}

	p.State.pedersenVerifications = make(map[types.SharingID][]pedersen_comm.Commitment)
	p.State.pedersenShares, p.State.polynomialCoefficients, p.State.pedersenVerifications[p.MySharingId], err = p.State.pedersenVss.DealWithPolynomial(zi, p.Prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot deal zi")
	}

	p.Round++
	return &Round1Broadcast{
		PedersenVerification: p.State.pedersenVerifications[p.MySharingId],
	}, nil
}

func (p *Participant) Round2(r2bi network.RoundMessages[types.ThresholdProtocol, *Round1Broadcast]) (r2bo *Round2Broadcast, r2uo network.RoundMessages[types.ThresholdProtocol, *Round2P2P], err error) {
	if p.Round != 2 {
		return nil, nil, errs.NewRound("Running round %d but participant expected round %d", 2, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.Protocol.Participants(), p.IdentityKey(), r2bi); err != nil {
		return nil, nil, errs.WrapValidation(err, "invalid round 2 input broadcast messages")
	}

	for sharingId, identityKey := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}

		inB, _ := r2bi.Get(identityKey)
		p.State.pedersenVerifications[sharingId] = inB.PedersenVerification
	}

	p.State.feldmanVerifications = make(map[types.SharingID][]curves.Point)
	_, p.State.feldmanVerifications[p.MySharingId], err = p.State.feldmanVss.DealPolynomial(p.State.polynomialCoefficients)
	if err != nil {
		return nil, nil, errs.NewFailed("cannot deal Feldman-VSS")
	}

	r2bo = &Round2Broadcast{
		FeldmanVerification: p.State.feldmanVerifications[p.MySharingId],
	}

	r2uo = network.NewRoundMessages[types.ThresholdProtocol, *Round2P2P]()
	for sharingId, identityKey := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}

		r2uo.Put(identityKey, &Round2P2P{PedersenShare: p.State.pedersenShares[sharingId]})
	}

	p.Round++
	return r2bo, r2uo, nil
}

func (p *Participant) Round3(r3bi network.RoundMessages[types.ThresholdProtocol, *Round2Broadcast], r3ui network.RoundMessages[types.ThresholdProtocol, *Round2P2P]) (signingKeyShare *tsignatures.SigningKeyShare, partialPublicKeys *tsignatures.PartialPublicKeys, err error) {
	if p.Round != 3 {
		return nil, nil, errs.NewRound("Running round %d but participant expected round %d", 3, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.Protocol.Participants(), p.IdentityKey(), r3bi); err != nil {
		return nil, nil, errs.WrapValidation(err, "invalid round 3 input broadcast messages")
	}
	if err := network.ValidateMessages(p.Protocol, p.Protocol.Participants(), p.IdentityKey(), r3ui); err != nil {
		return nil, nil, errs.WrapValidation(err, "invalid round 3 input P2P messages")
	}

	for sharingId, identityKey := range p.SharingCfg.Iter() {
		if sharingId == p.MySharingId {
			continue
		}

		inB, _ := r3bi.Get(identityKey)
		inU, _ := r3ui.Get(identityKey)
		p.State.feldmanVerifications[sharingId] = inB.FeldmanVerification

		if err := p.State.pedersenVss.VerifyShare(inU.PedersenShare, p.State.pedersenVerifications[sharingId]); err != nil {
			return nil, nil, errs.WrapIdentifiableAbort(err, identityKey.String(), "abort from pedersen")
		}
		if err := p.State.feldmanVss.VerifyShare(&inU.PedersenShare.ShamirShare, p.State.feldmanVerifications[sharingId]); err != nil {
			return nil, nil, errs.WrapIdentifiableAbort(err, identityKey.String(), "abort from feldman")
		}
		p.State.pedersenShares[sharingId] = inU.PedersenShare
	}

	pedersenShare := p.State.pedersenShares[p.MySharingId]
	feldmanVerificationVector := p.State.feldmanVerifications[p.MySharingId]
	for sharingId := range p.State.feldmanVerifications {
		if sharingId == p.MySharingId {
			continue
		}

		pedersenShare = p.State.pedersenVss.ShareAdd(pedersenShare, p.State.pedersenShares[sharingId])
		feldmanVerificationVector = p.State.feldmanVss.VerificationAdd(feldmanVerificationVector, p.State.feldmanVerifications[sharingId])
	}

	signingKeyShare = &tsignatures.SigningKeyShare{
		Share:     pedersenShare.ShamirShare.Value,
		PublicKey: feldmanVerificationVector[0],
	}
	partialPublicKeys = &tsignatures.PartialPublicKeys{
		PublicKey:               feldmanVerificationVector[0],
		Shares:                  hashmap.NewComparableHashMap[types.SharingID, curves.Point](),
		FeldmanCommitmentVector: feldmanVerificationVector,
	}
	for sharingId := range p.SharingCfg.Iter() {
		y := polynomials.EvalInExponent(feldmanVerificationVector, sharingId.ToScalar(p.Protocol.Curve().ScalarField()))
		partialPublicKeys.Shares.Put(sharingId, y)
	}

	p.Round++
	return signingKeyShare, partialPublicKeys, nil
}
